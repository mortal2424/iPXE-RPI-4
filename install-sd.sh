#!/bin/busybox sh
# Included in a signed, device-specific RAM image along with /install.conf.
# The job claim is made only after the complete payload has been verified.
set -eu
set -o pipefail
bb=/bin/busybox
. /install.conf
disk=/dev/mmcblk0
payload=/run/os.img.xz

fail() {
    echo "PI FLEET: $*" >&2
    exit 1
}

case "${PI_BOARD:-pi4b}" in
    pi4b) compatible=raspberrypi,4-model-b ;;
    cm4) compatible=raspberrypi,4-compute-module ;;
    *) fail "Unsupported board" ;;
esac
"$bb" tr '\000' '\n' </proc/device-tree/compatible |
    "$bb" grep -Fx "$compatible" >/dev/null || fail "Board identity mismatch"

for attempt in $("$bb" seq 1 30); do
    if [ -b "$disk" ] && [ -r /sys/block/mmcblk0/device/cid ] && [ -r /sys/class/net/eth0/address ]; then
        break
    fi
    "$bb" sleep 1
done
[ -b "$disk" ] || fail "No SD card"
[ -r /sys/class/net/eth0/address ] || fail "No Ethernet interface"
[ "$("$bb" cat /sys/block/mmcblk0/device/type)" = SD ] || fail "Target is not SD"
[ "$("$bb" cat /sys/block/mmcblk0/device/cid)" = "$SD_CID" ] || fail "SD card identity mismatch"
[ "$("$bb" cat /sys/class/net/eth0/address)" = "$PI_MAC" ] || fail "Pi identity mismatch"
if "$bb" grep -q '^/dev/mmcblk0' /proc/mounts; then
    fail "SD card is mounted"
fi
sectors=$("$bb" cat /sys/block/mmcblk0/size)
[ "$((sectors * 512))" -ge "$IMAGE_BYTES" ] || fail "SD card is too small"

"$bb" ip link set eth0 up
"$bb" ip addr add "$PI_ADDRESS" dev eth0
if [ -n "${PI_GATEWAY:-}" ]; then
    "$bb" ip route add "$BOOT_SERVER/32" via "$PI_GATEWAY" dev eth0
fi
for attempt in $("$bb" seq 1 20); do
    [ "$("$bb" cat /sys/class/net/eth0/carrier)" = 1 ] && break
    "$bb" sleep 1
done
[ "$("$bb" cat /sys/class/net/eth0/carrier)" = 1 ] || fail "No Ethernet link"
echo "PI FLEET: downloading and verifying image"
"$bb" mount -t tmpfs -o "size=$((PAYLOAD_BYTES + 1048576))" tmpfs /run
"$bb" wget -T 30 -O "$payload" "$IMAGE_URL"
[ "$("$bb" wc -c < "$payload")" -eq "$PAYLOAD_BYTES" ] || fail "Unexpected download size"
echo "$IMAGE_SHA256  $payload" | "$bb" sha256sum -c -
claim=$("$bb" wget -T 10 -O - --post-data="token=$JOB_TOKEN" "$CLAIM_URL")
[ "$claim" = "$JOB_TOKEN" ] || fail "Job claim rejected"

outcome=failed
report_result() {
    if [ -n "${RESULT_URL:-}" ]; then
        for attempt in 1 2 3; do
            "$bb" wget -T 5 -q -O /dev/null --post-data="token=$JOB_TOKEN&state=$outcome" "$RESULT_URL" && return
        done
    fi
}
trap report_result EXIT
echo "PI FLEET: writing OS image to SD"
"$bb" xz -dc "$payload" | "$bb" dd of="$disk" bs=1M iflag=fullblock conv=fsync
"$bb" sync
echo "PI FLEET: verifying the SD card by reading it back"
echo 3 > /proc/sys/vm/drop_caches
readback=$("$bb" head -c "$IMAGE_BYTES" "$disk" | "$bb" sha256sum)
[ "${readback%% *}" = "$RAW_IMAGE_SHA256" ] || fail "SD verification failed"
outcome=complete
echo "PI FLEET: write complete, rebooting"
