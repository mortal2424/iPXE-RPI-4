"""Expose the real Linux tty1 console over authenticated TLS VNC using saved SSH."""
import re
import shlex

import paramiko
from telemetry import connect

PORT = 5909
INSTALL = r'''
set -eu
umask 077
read -r vnc_password
login=$1
[ "$(id -u "$login")" -ne 0 ] || exit 40
. /etc/os-release
case "$ID" in debian|ubuntu|raspbian) ;; *) exit 41 ;; esac
[ -c /dev/tty1 ] && [ -c /dev/vcsa1 ] || exit 46
config=/etc/pi-fleet-vnc
if [ -e "$config/owner" ] && [ "$(cat "$config/owner")" != "$login" ]; then exit 42; fi
if ! systemctl is-active --quiet pi-fleet-vnc.service; then
    if ss -H -ltn 'sport = :5909' | grep -q .; then exit 43; fi
fi
install -d -m 0700 "$config"
printf '%s\n' "$login" > "$config/owner"
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=90 update >/var/log/pi-fleet-vnc-install.log 2>&1 || exit 44
apt-get -o DPkg::Lock::Timeout=90 install -y --no-install-recommends x11vnc tigervnc-tools openssl kmod kbd >>/var/log/pi-fleet-vnc-install.log 2>&1 || exit 44
[ -c /dev/uinput ] || modprobe uinput || exit 47
[ -c /dev/uinput ] || exit 47
printf 'uinput\n' > /etc/modules-load.d/pi-fleet-vnc.conf
password_file=$(mktemp "$config/passwd.XXXXXX")
trap 'rm -f "$password_file"' EXIT
printf '%s\n' "$vnc_password" | tigervncpasswd -f > "$password_file"
unset vnc_password
chmod 0600 "$password_file"
mv "$password_file" "$config/passwd"
if [ ! -s "$config/server.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=Pi-Fleet-console -keyout "$config/server.key" -out "$config/server.crt" >>/var/log/pi-fleet-vnc-install.log 2>&1
    cat "$config/server.key" "$config/server.crt" > "$config/server.pem"
    rm -f "$config/server.key"
    chmod 0600 "$config/server.pem"
fi
cat > /etc/systemd/system/pi-fleet-vnc.service <<'UNIT'
[Unit]
Description=Pi Fleet local tty1 console over VNC
After=network.target getty@tty1.service
Wants=getty@tty1.service
StartLimitIntervalSec=60
StartLimitBurst=5
[Service]
Type=simple
User=root
ExecStartPre=/bin/sh -c 'test -c /dev/uinput || /sbin/modprobe uinput'
ExecStartPre=/usr/bin/chvt 1
ExecStart=/usr/bin/x11vnc -rawfb vt1 -pipeinput UINPUT:K,/dev/uinput -rfbport 5909 -rfbauth /etc/pi-fleet-vnc/passwd -ssl /etc/pi-fleet-vnc/server.pem -vencrypt nodh:only -anontls never -forever -shared -nocursor
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now getty@tty1.service >/dev/null 2>&1
systemctl enable pi-fleet-vnc.service >/dev/null 2>&1
systemctl restart pi-fleet-vnc.service
for attempt in $(seq 1 30); do
    if systemctl is-active --quiet pi-fleet-vnc.service && ss -H -ltn 'sport = :5909' | grep -q .; then exit 0; fi
    sleep 1
done
exit 45
'''

ERRORS = {
    40: "Для VNC используйте обычного пользователя с sudo, не root.",
    41: "Поддерживаются Debian, Raspberry Pi OS и Ubuntu с обычным домашним каталогом.",
    42: "VNC Pi Fleet уже настроен для другого пользователя.",
    43: "Порт 5909 занят другим сервером. Настройки не изменены.",
    44: "Не удалось установить пакеты. Журнал на Pi: /var/log/pi-fleet-vnc-install.log.",
    46: "Локальная консоль tty1/vcsa1 недоступна. На этой системе VNC текстовой консоли не поддерживается.",
    47: "Не удалось включить uinput для управления клавиатурой локальной консоли.",
    45: "Пакеты установлены, но VNC не запустился. Проверьте journalctl -u pi-fleet-vnc.service на Pi.",
}


def install(ip, login, fingerprint, password, vnc_password):
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", login):
        raise ValueError("Некорректный логин SSH для VNC.")
    if not re.fullmatch(r"[!-~]{8}", vnc_password):
        raise ValueError("Пароль VNC должен состоять ровно из 8 печатных латинских символов, цифр или знаков.")
    if any(c in password for c in "\r\n\0"):
        raise ValueError("Обновите сохранённый пароль SSH.")
    command = shlex.join(["sudo", "-S", "-p", "", "/bin/sh", "-c", INSTALL, "pi-fleet-vnc", login])
    with connect(ip, login, fingerprint, password=password) as client:
        stdin, stdout, stderr = client.exec_command(command, timeout=900)
        stdin.write(password + "\n" + vnc_password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()
        stdout.read(16384)
        stderr.read(16384)
        code = stdout.channel.recv_exit_status()
    if code:
        raise paramiko.SSHException(ERRORS.get(code, "Установка VNC не завершилась. Проверьте пароль sudo и журнал на Pi."))
