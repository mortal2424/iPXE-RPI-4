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
cm4=0
model=$(tr -d '\000' </proc/device-tree/model)
case "$model" in
    'Raspberry Pi 4 Model B'*) ;;
    'Raspberry Pi Compute Module 4 Rev '*) cm4=1 ;;
    *) exit 20 ;;
esac
[ ! -e /run/rpi-eeprom-update-pending ] || exit 21
for path in /boot /boot/firmware; do
    for file in recovery.bin pieeprom.upd pieeprom.sig; do
        [ ! -e "$path/$file" ] || exit 21
    done
done
version_info=$(vcgencmd bootloader_version)
version=$(printf '%s\n' "$version_info" | sed -n '1s@^\([0-9]\{4\}\)/\([0-9]\{2\}\)/\([0-9]\{2\}\).*@\1-\2-\3@p')
[ -n "$version" ] && [ "$version" \> 2022-03-09 ] || exit 22
firmware=$(find /lib/firmware/raspberrypi/bootloader-2711 -name "pieeprom-$version.bin" -type f -print -quit)
if [ "$cm4" = 1 ]; then
    [ -n "$firmware" ] || firmware="/var/lib/pi-fleet-eeprom/firmware/pieeprom-$version.bin"
fi
[ -r "$firmware" ] || exit 22
command -v systemd-run >/dev/null && command -v systemctl >/dev/null || exit 27
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rpi-eeprom-config > "$work/original.conf"
if [ "$cm4" = 1 ]; then
    boot_timestamp=$(printf '%s\n' "$version_info" | awk '$1 == "timestamp" {print $2; exit}')
    boot_commit=$(printf '%s\n' "$version_info" | awk '$1 == "version" {print substr($2,1,8); exit}')
    case "$boot_timestamp" in ''|*[!0-9]*) exit 28 ;; esac
    [ "$boot_timestamp" -ge 1650968668 ] && [ "${#boot_commit}" = 8 ] || exit 28
    strings "$firmware" > "$work/firmware-strings"
    grep -Fxq "BUILD_TIMESTAMP=$boot_timestamp" "$work/firmware-strings" &&
        grep -Fq "VERSION:$boot_commit" "$work/firmware-strings" || exit 22
    grep -Eq '^[[:space:]]*ENABLE_SELF_UPDATE[[:space:]]*=[[:space:]]*1[[:space:]]*$' "$work/original.conf" || exit 28
    if grep -Eq '^[[:space:]]*(FREEZE_VERSION[[:space:]]*=[[:space:]]*1|ENABLE_SELF_UPDATE[[:space:]]*=[[:space:]]*0)' "$work/original.conf"; then
        exit 28
    fi
    [ "$(cat /sys/block/mmcblk0/device/type 2>/dev/null)" = SD ] || exit 29
    bootfs=/boot/firmware
    [ "$(findmnt -n -o SOURCE,FSTYPE --mountpoint "$bootfs")" = "/dev/mmcblk0p1 vfat" ] || exit 29
    case "$(sed -n 's/^[[:space:]]*BOOT_ORDER[[:space:]]*=[[:space:]]*//p' "$work/original.conf")" in
        0x*[17]) ;;
        *) exit 29 ;;
    esac
    if grep -Eq '^[[:space:]]*(include[[:space:]]|bootloader_update[[:space:]]*=[[:space:]]*0)' "$bootfs/config.txt"; then
        exit 29
    fi
    # Local updater defaults must not override the per-call staging mode.
    if grep -Eq '^[[:space:]]*(export[[:space:]]+)?(CM4_ENABLE_RPI_EEPROM_UPDATE|RPI_EEPROM_(SELF_UPDATE|IMMEDIATE_UPDATE))[[:space:]]*=' /etc/default/rpi-eeprom-update 2>/dev/null; then
        exit 29
    fi
fi
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
if [ "$4" = check ]; then
    exit 0
fi
install -d -m 0700 /var/lib/pi-fleet-eeprom
install -m 0600 "$work/original.conf" /var/lib/pi-fleet-eeprom/"$(date +%Y%m%dT%H%M%S)".conf
if [ "$cm4" = 1 ]; then
    CM4_ENABLE_RPI_EEPROM_UPDATE=1 RPI_EEPROM_SELF_UPDATE=1 RPI_EEPROM_IMMEDIATE_UPDATE=0 \
        rpi-eeprom-update -d -f "$work/pieeprom.bin" || exit 25
    if [ -e "$bootfs/recovery.bin" ] || [ ! -s "$bootfs/pieeprom.upd" ] || [ ! -s "$bootfs/pieeprom.sig" ]; then
        CM4_ENABLE_RPI_EEPROM_UPDATE=1 RPI_EEPROM_IMMEDIATE_UPDATE=0 rpi-eeprom-update -r || true
        exit 25
    fi
    sync
else
    rpi-eeprom-update -d -f "$work/pieeprom.bin" || exit 25
fi
systemd-run --unit=pi-fleet-eeprom-reboot --on-active=10s /usr/bin/systemctl reboot || exit 26
"""

ERRORS = {
    20: "Поддерживаются Raspberry Pi 4 Model B и CM4 Lite.",
    21: "На Pi уже есть ожидающее обновление EEPROM.",
    22: "Совместимый файл текущей версии EEPROM не найден. Проверьте пакет rpi-eeprom.",
    23: "В EEPROM есть специальные настройки загрузки. Проверьте их вручную.",
    24: "Pi не смогла собрать файл EEPROM. Проверьте rpi-eeprom-config.",
    25: "Pi не смогла поставить обновление EEPROM в очередь.",
    26: "Обновление EEPROM подготовлено. Автоперезагрузка не запланирована. Перезагрузите Pi штатно.",
    28: "Для CM4 нужен совместимый загрузчик с ENABLE_SELF_UPDATE=1 и без FREEZE_VERSION=1.",
    29: "CM4 требует локальную загрузочную SD-карту и совместимые настройки rpi-eeprom-update.",
    27: "На Pi не найдены инструменты systemd для штатной перезагрузки.",
}


def read_settings(ip, login, fingerprint, password):
    with connect(ip, login, fingerprint, password=password) as client:
        return run(client, "vcgencmd bootloader_version && printf '\n' && vcgencmd bootloader_config")


def stage(ip, login, fingerprint, password, host, key_file, profile, *, check_only=False):
    host = str(ipaddress.IPv4Address(host))
    order = BOOT_ORDERS[profile][1]
    public_key = key_file.read_text().strip()
    if not re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----", public_key):
        raise ValueError("Invalid EEPROM public signing key")
    command = shlex.join(["sudo", "-S", "-p", "", "/bin/sh", "-c", STAGE, "pi-fleet-eeprom", host, public_key, order,
                          "check" if check_only else "apply"])
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


def schedule_reboot(client, password, unit):
    command = shlex.join([
        "sudo", "-S", "-p", "", "systemd-run", "--unit", unit,
        "--on-active=10s", "/usr/bin/systemctl", "reboot",
    ])
    stdin, stdout, stderr = client.exec_command(command, timeout=5)
    stdin.write(password + "\n")
    stdin.flush()
    stdin.channel.shutdown_write()
    stdout.read(4096)
    stderr.read(4096)
    if stdout.channel.recv_exit_status():
        raise paramiko.SSHException("Could not schedule reboot")


def provisioning_identity(ip, login, fingerprint, password, host):
    command = r"""
set -eu
case "$(tr -d '\000' </proc/device-tree/model)" in
    'Raspberry Pi 4 Model B'*) echo pi4b ;;
    'Raspberry Pi Compute Module 4 Rev '*) echo cm4 ;;
    *) echo unsupported; exit 0 ;;
esac
if [ "$(cat /sys/block/mmcblk0/device/type 2>/dev/null || true)" != SD ]; then
    echo no-sd
    exit 0
fi
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
    board, _, identity = output.partition("\n")
    if board not in ("pi4b", "cm4"):
        raise ValueError("Поддерживаются Raspberry Pi 4 Model B и CM4 Lite с SD-картой.")
    if identity.strip() == "no-sd":
        raise ValueError("На mmcblk0 не обнаружена SD-карта. Запись на eMMC и NVMe не поддерживается.")
    cid, mac, memory, config = identity.split("\n", 3)
    settings = dict(line.split("=", 1) for line in config.splitlines() if "=" in line)
    if (settings.get("BOOT_ORDER", "").strip().lower()[-1:] != "7"
            or settings.get("HTTP_HOST") != host or settings.get("HTTP_PORT") != "8083"
            or settings.get("HTTP_PATH") != "/boot"):
        raise ValueError("В EEPROM выберите «Сеть HTTP → SD», примените настройки и повторите проверку.")
    if not re.fullmatch(r"[a-f0-9]{32}", cid) or not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac):
        raise ValueError("Не удалось прочитать MAC Ethernet или CID SD.")
    return cid, mac, min(4 * 1024**3, int(memory) * 512), board
