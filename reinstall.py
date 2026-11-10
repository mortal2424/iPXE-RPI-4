"""Validate and process one device-bound installation request on the provisioner."""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from poe import Switch

IMAGES = {
    "raspios-lite-arm64": "Raspberry Pi OS Lite · 64-bit",
    "ubuntu-server-24.04": "Ubuntu Server 24.04 LTS · 64-bit",
}
ACTIVE = ("queued", "preparing", "waiting", "writing", "uncertain")
STATES = {
    "queued": "В очереди",
    "preparing": "Подготовка образа",
    "waiting": "Ожидание загрузки установщика",
    "writing": "Запись или проверка SD",
    "complete": "Образ записан и проверен",
    "failed": "Установка завершилась ошибкой",
    "uncertain": "Нет результата записи. Проверьте экран Pi перед отключением питания.",
}


def schema(db):
    db.execute("""CREATE TABLE IF NOT EXISTS reinstall (
        id INTEGER PRIMARY KEY CHECK(id=1), ip TEXT NOT NULL, image TEXT NOT NULL,
        hostname TEXT NOT NULL, login TEXT NOT NULL, password_hash TEXT NOT NULL,
        status TEXT NOT NULL
    )""")


def valid_account(hostname, login):
    return (
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", hostname)
        and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", login)
        and login != "root"
    )


def cloud_config(image, hostname, login, password_hash):
    if image not in IMAGES or not valid_account(hostname, login) or not re.fullmatch(
        r"\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}", password_hash
    ):
        raise ValueError("Invalid installation parameters")
    config = {
        "hostname": hostname, "manage_etc_hosts": True, "ssh_pwauth": True,
        "users": [{"name": login, "shell": "/bin/bash", "groups": ["sudo"],
                   "passwd": password_hash, "lock_passwd": False}],
    }
    if image == "raspios-lite-arm64":
        config["enable_ssh"] = True
    else:
        config["runcmd"] = [["systemctl", "enable", "--now", "ssh.service"]]
    return "#cloud-config\n" + json.dumps(config, indent=2) + "\n"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def personalize(source, raw, user_data, mountpoint):
    with raw.open("wb") as output:
        run("xz", "-dc", source, stdout=output)
    loop = run("losetup", "--find", "--show", "--partscan", raw,
               capture_output=True, text=True).stdout.strip()
    try:
        run("udevadm", "settle")
        run("mount", "-t", "vfat", loop + "p1", mountpoint)
        try:
            seed = mountpoint / "user-data"
            if not seed.is_file():
                raise ValueError("No cloud-init seed in image")
            seed.write_text(user_data)
        finally:
            run("umount", mountpoint)
    finally:
        run("losetup", "-d", loop)


def process(db, base, state, settings, request):
    ip, image, hostname, login, password_hash = request
    if ip != str(ipaddress.IPv4Address(settings["ip"])):
        raise ValueError("Pi is not registered for installation")
    device = db.execute("SELECT physical_port, sd_cid FROM devices WHERE ip=?", (ip,)).fetchone()
    if not device or device[0] != settings["port"] or not device[1]:
        raise ValueError("SD card or verified port not registered")
    cid, mac = device[1], settings["mac"]
    if not re.fullmatch(r"[a-f0-9]{32}", cid) or not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac):
        raise ValueError("Invalid device identity")
    server = str(ipaddress.IPv4Address(settings["server"]))
    address = ipaddress.IPv4Interface(f"{ip}/{settings['prefix']}")
    switch = Switch(state / "switch")
    if not switch.allow_write or switch.ports.get(ip, (None,))[0] != settings["port"]:
        raise ValueError("No verified PoE control for this device")
    source = base / "images" / (image + ".img.xz")
    config = cloud_config(image, hostname, login, password_hash)
    jobs = state / "state/jobs"
    publish = state / "boot"
    payload = state / "images/reinstall.img.xz"
    token = secrets.token_hex(32)
    pending = jobs / (token + ".pending")
    claimed = pending.with_suffix(".claimed")
    result = pending.with_suffix(".result")
    claim_consumed = False

    def status(value):
        with db:
            db.execute("UPDATE reinstall SET status=?, password_hash='' WHERE id=1", (value,))

    if (publish / "boot.sig").exists():
        raise ValueError("Another boot image is already published")
    try:
        with tempfile.TemporaryDirectory(dir=base / "images") as directory:
            work = Path(directory)
            raw, fat, packed = work / "os.img", work / "fat", work / "os.img.xz"
            fat.mkdir()
            personalize(source, raw, config, fat)
            with packed.open("wb") as output:
                run("xz", "-T2", "-0", "-c", raw, stdout=output)
            max_payload = int(settings["max_payload_bytes"])
            if packed.stat().st_size > max_payload:
                raise ValueError("Selected image exceeds the registered Pi RAM budget")
            installer = work / "install.conf"
            installer.write_text(
                f"SD_CID={cid}\nPI_MAC={mac}\nPI_ADDRESS={address}\n"
                f"IMAGE_URL=http://{server}:8083/images/reinstall.img.xz\n"
                f"CLAIM_URL=http://{server}:8083/claim\n"
                f"RESULT_URL=http://{server}:8083/result\n"
                f"IMAGE_SHA256={digest(packed)}\nRAW_IMAGE_SHA256={digest(raw)}\n"
                f"IMAGE_BYTES={raw.stat().st_size}\nPAYLOAD_BYTES={packed.stat().st_size}\nJOB_TOKEN={token}\n"
            )
            run("bash", base / "build-probe.sh", base / "build", work / "boot.img", installer,
                env={**os.environ, "SD_MAX_HZ": "25000000"})
            run("bash", base / "build/rpi-eeprom-digest", "-i", work / "boot.img", "-o",
                work / "boot.sig", "-k", base / "build/signing.pem")
            run("install", "-m", "0644", packed, payload)
            run("install", "-m", "0644", work / "boot.img", publish / "boot.img")
            run("install", "-m", "0600", "-o", "10001", "-g", "10001", "/dev/null", pending)
            run("install", "-m", "0644", work / "boot.sig", publish / "boot.sig")
        status("waiting")
        switch.restart(ip)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline and not claimed.exists():
            time.sleep(1)
        if not claimed.exists():
            pending.unlink(missing_ok=True)
        claim_consumed = claimed.exists()
        if not claim_consumed:
            raise TimeoutError("Pi did not claim the installation")
        (publish / "boot.sig").unlink(missing_ok=True)
        status("writing")
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            if result.exists():
                outcome = result.read_text().strip()
                status("complete" if outcome == "complete" else "failed")
                return
            time.sleep(2)
        status("uncertain")
    finally:
        for file in (pending, publish / "boot.sig", publish / "boot.img", payload):
            file.unlink(missing_ok=True)
        if not claim_consumed and claimed.exists():
            status("uncertain")


def main():
    base, state = Path("/opt/pi-reinstall"), Path("/srv/pi-reinstall")
    settings = json.loads((base / "install-device.json").read_text())
    with sqlite3.connect(state / "state/devices.db") as db:
        schema(db)
        db.execute("BEGIN IMMEDIATE")
        request = db.execute(
            "SELECT ip,image,hostname,login,password_hash FROM reinstall WHERE status='queued'"
        ).fetchone()
        if not request:
            return
        db.execute("UPDATE reinstall SET status='preparing',password_hash='' WHERE id=1")
    try:
        process(db, base, state, settings, request)
    except Exception as error:
        print(f"Installation error: {type(error).__name__}", flush=True)
        with db:
            db.execute("UPDATE reinstall SET status=CASE WHEN status IN ('waiting','writing','uncertain') THEN 'uncertain' ELSE 'failed' END WHERE id=1")
        raise SystemExit(1) from None
    finally:
        db.close()


if __name__ == "__main__":
    main()
