"""Validate and process one device-bound installation request on the provisioner."""
import base64
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

from poe import PoeError, Switch

IMAGES = {
    "raspios-lite-arm64": "Raspberry Pi OS Lite · 64-bit",
    "raspios-desktop-arm64": "Raspberry Pi OS Desktop · 64-bit",
    "ubuntu-server-24.04": "Ubuntu Server 24.04 LTS · 64-bit",
}
RAW_IMAGES = {
    "dietpi-arm64": {"pi4b", "cm4"},
    "debian-arm64": {"pi4b"},
    "openwrt-arm64": {"pi4b", "cm4"},
    "home-assistant-os": {"pi4b"},
    "libreelec-arm64": {"pi4b", "cm4"},
}
IMAGES.update({
    "dietpi-arm64": "DietPi · 64-bit",
    "debian-arm64": "Debian · 64-bit",
    "openwrt-arm64": "OpenWrt · 64-bit",
    "home-assistant-os": "Home Assistant OS · 64-bit",
    "libreelec-arm64": "LibreELEC · 64-bit",
})
PI_OS_IMAGES = {"raspios-lite-arm64", "raspios-desktop-arm64"}


def supports_board(image, board):
    return image in IMAGES and board in RAW_IMAGES.get(image, {"pi4b", "cm4"})


ACTIVE = ("queued", "preparing", "ssh_restart", "restart_fallback", "manual_restart", "waiting", "writing", "uncertain")
STATES = {
    "queued": "В очереди",
    "preparing": "Подготовка образа",
    "ssh_restart": "Установщик готов. Проверяем возможность перезапуска по SSH.",
    "restart_fallback": "Перезапуск по SSH недоступен. Проверяем управление питанием.",
    "manual_restart": "Установщик готов. Сейчас выключите и снова включите питание Pi вручную.",
    "restart_timeout": "Pi не загрузила установщик вовремя. Запустите переустановку заново.",
    "waiting": "Ожидание загрузки установщика",
    "writing": "Запись или проверка SD",
    "complete": "Образ записан и проверен",
    "failed": "Установка завершилась ошибкой",
    "uncertain": "Нет результата записи. Проверьте экран Pi перед отключением питания.",
}


def schema(db):
    db.execute("CREATE TABLE IF NOT EXISTS provisioning (ip TEXT PRIMARY KEY, mac TEXT NOT NULL, max_payload INTEGER NOT NULL)")
    if "board" not in {row[1] for row in db.execute("PRAGMA table_info(provisioning)")}:
        db.execute("ALTER TABLE provisioning ADD COLUMN board TEXT NOT NULL DEFAULT 'pi4b'")
    db.execute("""CREATE TABLE IF NOT EXISTS reinstall (
        id INTEGER PRIMARY KEY CHECK(id=1), ip TEXT NOT NULL, image TEXT NOT NULL,
        hostname TEXT NOT NULL, login TEXT NOT NULL, password_hash TEXT NOT NULL,
        status TEXT NOT NULL
    )""")

    if "network_json" not in {row[1] for row in db.execute("PRAGMA table_info(reinstall)")}:
        db.execute("ALTER TABLE reinstall ADD COLUMN network_json TEXT NOT NULL DEFAULT '{}'")

    if "restart_token" not in {row[1] for row in db.execute("PRAGMA table_info(reinstall)")}:
        db.execute("ALTER TABLE reinstall ADD COLUMN restart_token TEXT")

    db.execute("""CREATE TABLE IF NOT EXISTS reinstall_ssh (
        ip TEXT PRIMARY KEY, login TEXT NOT NULL, secret BLOB NOT NULL,
        mac TEXT NOT NULL, expires INTEGER, fingerprint TEXT
    )""")

    db.execute("""CREATE TABLE IF NOT EXISTS reinstall_networks (
        network TEXT PRIMARY KEY, gateway TEXT NOT NULL
    )""")


def parse_reinstall_networks(value, primary):
    """Extra installation networks and their on-link IPv4 gateways."""
    profiles = {}
    for line in value.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError("На каждой строке укажите подсеть CIDR и шлюз через пробел.")
        network = ipaddress.IPv4Network(parts[0])
        gateway = ipaddress.IPv4Address(parts[1])
        if (not 1 <= network.prefixlen <= 30 or not gateway in network
                or gateway in (network.network_address, network.broadcast_address)
                or gateway.is_unspecified or gateway.is_loopback or gateway.is_multicast
                or network.overlaps(primary)
                or any(network.overlaps(other) for other in profiles)):
            raise ValueError("Подсети не должны пересекаться. Шлюз должен быть адресом устройства внутри своей подсети.")
        profiles[network] = gateway
    return profiles


def reinstall_profile(ip, primary, profiles):
    address = ipaddress.IPv4Address(ip)
    for network, gateway in [(primary, None), *profiles.items()]:
        if address in network and address not in (network.network_address, network.broadcast_address, gateway):
            return network, gateway
    return None


def load_reinstall_networks(db, primary):
    rows = db.execute("SELECT network,gateway FROM reinstall_networks ORDER BY network").fetchall()
    return parse_reinstall_networks("\n".join(f"{network} {gateway}" for network, gateway in rows), primary)


def local_host_fingerprint(ip, mac):
    """Read an Ed25519 key from a Pi on the directly connected installation network."""
    route = json.loads(run("ip", "-j", "route", "get", ip, capture_output=True, text=True).stdout)[0]
    if "gateway" in route or route.get("type") == "local":
        raise ValueError("Pi is not on a directly connected link")
    scan = subprocess.run(["ssh-keyscan", "-T", "3", "-t", "ed25519", ip],
                          capture_output=True, text=True, timeout=5)
    neighbors = json.loads(run("ip", "-j", "neigh", "show", "to", ip, "dev", route["dev"],
                               capture_output=True, text=True).stdout)
    if not any(n.get("lladdr", "").lower() == mac.lower() for n in neighbors):
        raise ValueError("Pi Ethernet MAC did not match")
    for line in scan.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[:2] == [ip, "ssh-ed25519"]:
            digest = hashlib.sha256(base64.b64decode(fields[2], validate=True)).digest()
            return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    raise ValueError("Pi SSH host key is not available")


def discover_reinstalled_hosts(db):
    now = int(time.time())
    with db:
        db.execute("DELETE FROM reinstall_ssh WHERE expires <= ?", (now,))
    pending = db.execute("""SELECT ip, mac, expires FROM reinstall_ssh
                            WHERE expires > ? AND fingerprint IS NULL""", (now,)).fetchall()
    for ip, mac, expires in pending:
        try:
            fingerprint = local_host_fingerprint(ip, mac)
        except (ValueError, OSError, KeyError, IndexError, subprocess.SubprocessError):
            continue
        with db:
            db.execute("UPDATE reinstall_ssh SET fingerprint=? WHERE ip=? AND expires=?",
                       (fingerprint, ip, expires))


def installation_network(ip, mode, address="", prefix=24, gateway="", dns=""):
    if mode == "dhcp":
        return {"mode": "dhcp"}
    if mode != "static":
        raise ValueError("Выберите статический IP или DHCP.")
    address = ipaddress.IPv4Address(address)
    interface = ipaddress.IPv4Interface(f"{address}/{int(prefix)}")
    route = ipaddress.IPv4Address(gateway)
    servers = [str(ipaddress.IPv4Address(value)) for value in dns.replace(",", " ").split()]
    if (str(address) != str(ip) or not 1 <= interface.network.prefixlen <= 30
            or address in (interface.network.network_address, interface.network.broadcast_address)
            or address.is_loopback or address.is_multicast or address.is_unspecified
            or route not in interface.network or route == address
            or route in (interface.network.network_address, interface.network.broadcast_address)
            or not 1 <= len(servers) <= 3
            or any(ipaddress.IPv4Address(value).is_loopback or ipaddress.IPv4Address(value).is_multicast
                   or ipaddress.IPv4Address(value).is_unspecified for value in servers)):
        raise ValueError("Проверьте IP карточки, префикс, шлюз в той же сети и от 1 до 3 DNS-серверов.")
    return {"mode": "static", "address": str(address), "prefix": interface.network.prefixlen,
            "gateway": str(route), "dns": servers}


def network_config(image, mac, settings, ip):
    if image not in IMAGES or image in RAW_IMAGES or not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac):
        raise ValueError("Invalid network device")
    settings = installation_network(ip, settings.get("mode"), settings.get("address", ""),
                                    settings.get("prefix", 24), settings.get("gateway", ""),
                                    " ".join(settings.get("dns", [])))
    nic = {"match": {"macaddress": mac}, "dhcp4": settings["mode"] == "dhcp", "dhcp6": False}
    if settings["mode"] == "static":
        nic.update({"addresses": [f"{settings['address']}/{settings['prefix']}"],
                    "routes": [{"to": "0.0.0.0/0", "via": settings["gateway"]}],
                    "nameservers": {"addresses": settings["dns"]}})
    elif image == "ubuntu-server-24.04":
        nic["dhcp-identifier"] = "mac"
    config = {"version": 2, "renderer": "NetworkManager" if image in PI_OS_IMAGES else "networkd",
              "ethernets": {"fleet": nic}}
    return json.dumps(config, indent=2) + "\n"


def valid_account(hostname, login):
    return (
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", hostname)
        and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", login)
        and login != "root"
    )


def cloud_config(image, hostname, login, password_hash):
    if image not in IMAGES or image in RAW_IMAGES or not valid_account(hostname, login) or not re.fullmatch(
        r"\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}", password_hash
    ):
        raise ValueError("Invalid installation parameters")
    config = {
        "hostname": hostname, "manage_etc_hosts": True, "ssh_pwauth": True,
        "users": [{"name": login, "shell": "/bin/bash", "groups": ["sudo"],
                   "passwd": password_hash, "lock_passwd": False}],
    }
    if image in PI_OS_IMAGES:
        config["enable_ssh"] = True
    else:
        config["runcmd"] = [["systemctl", "enable", "--now", "ssh.service"]]
    return "#cloud-config\n" + json.dumps(config, indent=2) + "\n"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def personalize(source, raw, user_data, mountpoint, network_data=None):
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
            if network_data is not None:
                (mountpoint / "network-config").write_text(network_data)
        finally:
            run("umount", mountpoint)
    finally:
        run("losetup", "-d", loop)


def restart_poe(db, state, ip, port, pending):
    if port is None or not pending.is_file():
        return False
    try:
        switch = Switch(state / "switch")
        switch.load_registrations(db)
        if switch.allow_write and switch.ports.get(ip, (None,))[0] == port and pending.is_file():
            switch.restart(ip)
            return True
    except (OSError, ValueError, KeyError, PoeError) as error:
        print(f"PoE restart unavailable: {type(error).__name__}", flush=True)
    return False


def process(db, base, state, settings, request):
    ip, image, hostname, login, password_hash, *extra = request
    network = json.loads(extra[0]) if extra else {}
    registered = db.execute("SELECT mac,max_payload,board FROM provisioning WHERE ip=?", (ip,)).fetchone()
    if registered:
        mac, max_payload, board = registered
    elif ip == str(ipaddress.IPv4Address(settings["ip"])):
        mac, max_payload, board = settings["mac"], int(settings["max_payload_bytes"]), "pi4b"
    else:
        raise ValueError("Pi is not registered for installation")
    device = db.execute("SELECT physical_port, sd_cid FROM devices WHERE ip=?", (ip,)).fetchone()
    if not device or not device[1]:
        raise ValueError("SD card not registered")
    port, cid = device
    if not re.fullmatch(r"[a-f0-9]{32}", cid) or not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac):
        raise ValueError("Invalid device identity")
    server = str(ipaddress.IPv4Address(settings["server"]))
    primary = ipaddress.IPv4Interface(f"{server}/{settings['prefix']}").network
    profile = reinstall_profile(ip, primary, load_reinstall_networks(db, primary))
    if not profile or ip == server:
        raise ValueError("Pi is outside the allowed installation networks")
    subnet, gateway = profile
    address = ipaddress.IPv4Interface(f"{ip}/{subnet.prefixlen}")
    if board not in ("pi4b", "cm4"):
        raise ValueError("Unsupported installer board")
    if board == "cm4" and not (base / "build/bcm2711-rpi-cm4.dtb").is_file():
        raise ValueError("CM4 device tree is missing from the installer")
    if not supports_board(image, board):
        raise ValueError("Image is unavailable for this board")
    source = base / "images" / (image + ".img.xz")
    raw_image = image in RAW_IMAGES
    config = None if raw_image else cloud_config(image, hostname, login, password_hash)
    network_data = network_config(image, mac, network, ip) if not raw_image and network else None
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
            db.execute("UPDATE reinstall SET status=?, password_hash='', restart_token=? WHERE id=1",
                       (value, token if value == "ssh_restart" else None))
            if value == "complete":
                db.execute("UPDATE reinstall_ssh SET expires=? WHERE ip=?",
                           (int(time.time()) + 3600, ip))
            elif value in ("failed", "uncertain", "restart_timeout"):
                db.execute("DELETE FROM reinstall_ssh WHERE ip=?", (ip,))

    if (publish / "boot.sig").exists():
        raise ValueError("Another boot image is already published")
    try:
        with tempfile.TemporaryDirectory(dir=base / "images") as directory:
            work = Path(directory)
            raw, fat, packed = work / "os.img", work / "fat", work / "os.img.xz"
            fat.mkdir()
            if raw_image:
                packed = source
                if packed.stat().st_size > max_payload:
                    raise ValueError("Selected image exceeds the registered Pi RAM budget")
                with raw.open("wb") as output:
                    run("xz", "-dc", packed, stdout=output)
            else:
                personalize(source, raw, config, fat, network_data)
                with packed.open("wb") as output:
                    run("xz", "-T2", "-0", "-c", raw, stdout=output)
            if packed.stat().st_size > max_payload:
                raise ValueError("Selected image exceeds the registered Pi RAM budget")
            installer = work / "install.conf"
            installer.write_text(
                f"SD_CID={cid}\nPI_MAC={mac}\nPI_ADDRESS={address}\nPI_BOARD={board}\n"
                f"BOOT_SERVER={server}\nPI_GATEWAY={gateway or ''}\n"
                f"IMAGE_URL=http://{server}:8083/images/reinstall.img.xz\n"
                f"CLAIM_URL=http://{server}:8083/claim\n"
                f"RESULT_URL=http://{server}:8083/result\n"
                f"IMAGE_SHA256={digest(packed)}\nRAW_IMAGE_SHA256={digest(raw)}\n"
                f"IMAGE_BYTES={raw.stat().st_size}\nPAYLOAD_BYTES={packed.stat().st_size}\nJOB_TOKEN={token}\n"
            )
            run("bash", base / "build-probe.sh", base / "build", work / "boot.img", installer,
                env={**os.environ, "SD_MAX_HZ": "25000000", "PI_BOARD": board})
            run("bash", base / "build/rpi-eeprom-digest", "-i", work / "boot.img", "-o",
                work / "boot.sig", "-k", base / "build/signing.pem")
            run("install", "-m", "0644", packed, payload)
            run("install", "-m", "0644", work / "boot.img", publish / "boot.img")
            run("install", "-m", "0600", "-o", "10001", "-g", "10001", "/dev/null", pending)
            target = work / "target.ip"
            target.write_text(ip + "\n")
            run("install", "-m", "0644", target, publish / "target.ip")
            run("install", "-m", "0644", work / "boot.sig", publish / "boot.sig")
        status("ssh_restart")
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline and not claimed.exists():
            current = db.execute("SELECT status FROM reinstall WHERE id=1").fetchone()[0]
            if current == "restart_fallback":
                status("manual_restart" if not restart_poe(db, state, ip, port, pending) else "waiting")
            time.sleep(1)
        if not claimed.exists():
            pending.unlink(missing_ok=True)
        claim_consumed = claimed.exists()
        if not claim_consumed:
            status("restart_timeout")
            return
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
        for file in (pending, publish / "boot.sig", publish / "boot.img", payload, publish / "target.ip"):
            file.unlink(missing_ok=True)
        if not claim_consumed and claimed.exists():
            status("uncertain")


def main():
    base, state = Path("/opt/pi-reinstall"), Path("/srv/pi-reinstall")
    settings = json.loads((base / "install-device.json").read_text())
    with sqlite3.connect(state / "state/devices.db") as db:
        schema(db)
        discover_reinstalled_hosts(db)
        db.execute("BEGIN IMMEDIATE")
        request = db.execute(
            "SELECT ip,image,hostname,login,password_hash,network_json FROM reinstall WHERE status='queued'"
        ).fetchone()
        if not request:
            return
        db.execute("UPDATE reinstall SET status='preparing',password_hash='' WHERE id=1")
    try:
        process(db, base, state, settings, request)
    except Exception as error:
        print(f"Installation error: {type(error).__name__}", flush=True)
        with db:
            db.execute("DELETE FROM reinstall_ssh WHERE ip=?", (request[0],))
            db.execute("UPDATE reinstall SET status=CASE WHEN status IN ('waiting','writing','uncertain') THEN 'uncertain' ELSE 'failed' END WHERE id=1")
        raise SystemExit(1) from None
    finally:
        db.close()


if __name__ == "__main__":
    main()
