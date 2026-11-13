#!/bin/bash
# Run on Linux as root. Input contains Pi boot files, busybox, and its libraries.
set -euo pipefail
input=$(realpath "$1")
output=$(realpath -m "$2")
work=$(mktemp -d)
trap 'mountpoint -q "$work/fat" && umount "$work/fat"; rm -rf "$work"' EXIT
mkdir -p "$work/root/run" "$work/fat" "$work/root/bin" "$work/root/dev" "$work/root/proc" "$work/root/sys"
cp -a "$input/lib" "$work/root/"
cp "$input/busybox" "$work/root/bin/"
mknod "$work/root/dev/console" c 5 1
cat > "$work/root/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
if [ -f /install.conf ]; then
    if /bin/busybox sh /install-sd.sh; then
        /bin/busybox sleep 10
    else
        echo 'PI FLEET: installation failed. Rebooting in 60 seconds.'
        /bin/busybox sleep 60
    fi
else
    echo 'PI REINSTALL PROBE: Linux is running in RAM. SD was not written.'
    /bin/busybox sleep 120
fi
/bin/busybox reboot -f
while true; do /bin/busybox sleep 60; done
INIT
chmod 0755 "$work/root/init"
if [ "$#" -eq 3 ]; then
    install -m 0600 "$3" "$work/root/install.conf"
    install -m 0755 "$(dirname "$0")/install-sd.sh" "$work/root/install-sd.sh"
fi
(cd "$work/root" && find . -print0 | cpio --null -o -H newc --quiet | gzip -n) > "$work/probe.gz"
truncate -s 32M "$output"
mkfs.vfat "$output"
mount -o loop "$output" "$work/fat"
cp "$input"/{start4.elf,fixup4.dat,kernel8.img,bcm2711-rpi-4-b.dtb} "$work/fat/"
cp "$work/probe.gz" "$work/fat/"
if [ -n "${SD_MAX_HZ:-}" ]; then
    dtb="$work/fat/bcm2711-rpi-4-b.dtb"
    controller=$(fdtget -t s "$dtb" /__symbols__ emmc2)
    fdtput -t u "$dtb" "$controller" max-frequency "$SD_MAX_HZ"
    fdtput "$dtb" "$controller" no-1-8-v
fi
cat > "$work/fat/config.txt" <<'CONFIG'
arm_64bit=1
kernel=kernel8.img
initramfs probe.gz followkernel
CONFIG
echo 'console=tty1 rdinit=/init' > "$work/fat/cmdline.txt"
umount "$work/fat"
