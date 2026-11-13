"""Stage the Raspberry Pi 4 HTTP boot configuration over verified SSH."""
import ipaddress
import re
import shlex

import paramiko

from telemetry import connect, run

BOOT_ORDERS = {
    "http-sd": ("Сеть HTTP → SD", "0xf17"),
    "sd-http": ("SD → сеть HTTP", "0xf71"),
    "sd-usb": ("SD → USB", "0xf41"),
    "usb-sd": ("USB → SD", "0xf14"),
    "sd": ("Только SD", "0xf1"),
}

STAGE = r"""
set -eu
umask 077
model=$(tr -d '\000' </proc/device-tree/model)
case "$model" in 'Raspberry Pi 4 Model B'*) ;; *) exit 20 ;; esac
for path in /boot /boot/firmware; do
    for file in recovery.bin pieeprom.upd pieeprom.sig; do
        [ ! -e "$path/$file" ] || exit 21
    done
done
version=$(vcgencmd bootloader_version | sed -n '1s@^\([0-9]\{4\}\)/\([0-9]\{2\}\)/\([0-9]\{2\}\).*@\1-\2-\3@p')
[ -n "$version" ] && [ "$version" \> 2022-03-09 ] || exit 22
firmware=$(find /lib/firmware/raspberrypi/bootloader-2711 -name "pieeprom-$version.bin" -type f -print -quit)
[ -n "$firmware" ] || exit 22
command -v systemd-run >/dev/null && command -v systemctl >/dev/null || exit 27
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rpi-eeprom-config > "$work/original.conf"
awk -v host="$1" -v boot_order="$3" '
    /^[[:space:]]*\[/ && $0 !~ /^[[:space:]]*\[all\][[:space:]]*$/ { invalid=1 }
    /^[[:space:]]*(SIGNED_BOOT|HTTP_CACERT_HASH)[[:space:]]*=/ { invalid=1 }
    /^[[:space:]]*(BOOT_ORDER|HTTP_HOST|HTTP_PORT|HTTP_PATH|NET_INSTALL_AT_POWER_ON)[[:space:]]*=/ { next }
    { print }
    END {
        if (invalid) exit 1
        print "BOOT_ORDER=" boot_order
        print "HTTP_HOST=" host
        print "HTTP_PORT=8083"
        print "HTTP_PATH=/boot"
        print "NET_INSTALL_AT_POWER_ON=0"
    }
' "$work/original.conf" > "$work/boot.conf" || exit 23
printf '%s\n' "$2" > "$work/public.pem"
rpi-eeprom-config -c "$work/boot.conf" -p "$work/public.pem" -o "$work/pieeprom.bin" "$firmware" || exit 24
install -d -m 0700 /var/lib/pi-fleet-eeprom
install -m 0600 "$work/original.conf" /var/lib/pi-fleet-eeprom/"$(date +%Y%m%dT%H%M%S)".conf
rpi-eeprom-update -d -f "$work/pieeprom.bin" || exit 25
systemd-run --unit=pi-fleet-eeprom-reboot --on-active=10s /usr/bin/systemctl reboot || exit 26
"""

ERRORS = {
    20: "Поддерживается только Raspberry Pi 4 Model B.",
    21: "На Pi уже есть ожидающее обновление EEPROM.",
    22: "Совместимый файл текущей версии EEPROM не найден. Проверьте пакет rpi-eeprom.",
    23: "В EEPROM есть специальные настройки загрузки. Проверьте их вручную.",
    24: "Pi не смогла собрать файл EEPROM. Проверьте rpi-eeprom-config.",
    25: "Pi не смогла поставить обновление EEPROM в очередь.",
    26: "Обновление EEPROM подготовлено. Автоперезагрузка не запланирована. Перезагрузите Pi штатно.",
    27: "На Pi не найдены инструменты systemd для штатной перезагрузки.",
}


def read_settings(ip, login, fingerprint, password):
    with connect(ip, login, fingerprint, password=password) as client:
        return run(client, "vcgencmd bootloader_version && printf '\n' && vcgencmd bootloader_config")


def stage(ip, login, fingerprint, password, host, key_file, profile):
    host = str(ipaddress.IPv4Address(host))
    order = BOOT_ORDERS[profile][1]
    public_key = key_file.read_text().strip()
    if not re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----", public_key):
        raise ValueError("Invalid EEPROM public signing key")
    command = shlex.join(["sudo", "-S", "-p", "", "/bin/sh", "-c", STAGE, "pi-fleet-eeprom", host, public_key, order])
    with connect(ip, login, fingerprint, password=password) as client:
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        stdin.write(password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()
        # Output is bounded by the firmware tools. Only the status is shown to the user.
        stdout.read(16384)
        stderr.read(16384)
        code = stdout.channel.recv_exit_status()
    if code:
        raise paramiko.SSHException(ERRORS.get(code, "Проверьте пароль sudo и наличие утилит rpi-eeprom на Pi."))


def provisioning_identity(ip, login, fingerprint, password, host):
    command = r"""
set -eu
case "$(tr -d '\000' </proc/device-tree/model)" in 'Raspberry Pi 4 Model B'*) ;; *) exit 1 ;; esac
[ "$(cat /sys/block/mmcblk0/device/type)" = SD ]
cat /sys/block/mmcblk0/device/cid
for interface in eth0 end0; do
    if [ -r "/sys/class/net/$interface/address" ]; then
        cat "/sys/class/net/$interface/address"
        break
    fi
done
awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo
vcgencmd bootloader_config
"""
    with connect(ip, login, fingerprint, password=password) as client:
        output = run(client, command)
    cid, mac, memory, config = output.split("\n", 3)
    settings = dict(line.split("=", 1) for line in config.splitlines() if "=" in line)
    if (settings.get("BOOT_ORDER", "").strip().lower()[-1:] != "7"
            or settings.get("HTTP_HOST") != host or settings.get("HTTP_PORT") != "8083"
            or settings.get("HTTP_PATH") != "/boot"):
        raise ValueError("В EEPROM выберите «Сеть HTTP → SD», примените настройки и повторите проверку.")
    if not re.fullmatch(r"[a-f0-9]{32}", cid) or not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac):
        raise ValueError("Не удалось прочитать MAC Ethernet или CID SD.")
    return cid, mac, min(4 * 1024**3, int(memory) * 512)
