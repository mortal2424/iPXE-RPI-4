"""Local management panel for Pi provisioning."""
import argparse
import base64
import hashlib
import hmac
import ssl
from urllib.parse import urlsplit
import ipaddress
import re
import socket
import sqlite3
import subprocess
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html import escape
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import paramiko
from cryptography.fernet import Fernet, InvalidToken
import telemetry
import eeprom
import vnc
from poe import PoeError, Switch

from reinstall import ACTIVE, IMAGES, STATES, cloud_config, schema, valid_account, installation_network
from reinstall import load_reinstall_networks, parse_reinstall_networks, reinstall_profile
DASHBOARD_CSS = Path(__file__).with_name("dashboard.css").read_text()
BOOT = {"http-sd": "HTTP → SD", "sd-http": "SD → HTTP", "sd": "Только SD"}


def reachable(ip):
    try:
        with socket.create_connection((ip, 22), timeout=0.7):
            return True
    except OSError:
        return False


def options(items, selected):
    return "".join(f'<option value="{key}" {"selected" if key == selected else ""}>{label}</option>'
                   for key, label in items.items())


def poll(ip, login, fingerprint, private):
    if private:
        try:
            return ip, True, telemetry.collect(ip, login, fingerprint, private)
        except (OSError, ValueError, IndexError, KeyError, paramiko.SSHException):
            pass
    return ip, reachable(ip), None


def sample_devices(database):
    with sqlite3.connect(database) as db:
        devices = db.execute("SELECT d.ip, c.login, c.fingerprint, c.private FROM devices d LEFT JOIN collectors c USING(ip)").fetchall()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda device: poll(*device), devices))
    now = int(time.time())
    with sqlite3.connect(database) as db:
        db.executemany(
            "INSERT OR REPLACE INTO samples SELECT ip, ?, ? FROM devices WHERE ip = ?",
            [(now, online, ip) for ip, online, _ in results],
        )
        db.executemany(
            "INSERT OR REPLACE INTO metrics SELECT ip, ?, ?, ?, ?, ?, ?, ?, ? FROM collectors WHERE ip = ?",
            [(now, *metrics, ip) for ip, _, metrics in results if metrics is not None],
        )
        db.execute("DELETE FROM metrics WHERE checked < ?", (now - 86400,))
        db.execute("DELETE FROM samples WHERE checked < ?", (now - 7 * 86400,))


def submitted_fingerprint(data):
    value = data.get("fingerprint", [""])[0].strip()
    match = re.fullmatch(r"\d+ (SHA256:[A-Za-z0-9+/]{43})(?: .*)?", value)
    return match[1] if match else value


def valid_ssh(login, fingerprint, password):
    return (re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,31}", login)
            and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint)
            and 0 < len(password) <= 256 and not any(c in password for c in "\r\n\0"))


def save_ssh(db, ip, login, fingerprint, private, cipher, password):
    db.execute("INSERT OR REPLACE INTO collectors VALUES (?,?,?,?)", (ip, login, fingerprint, private))
    if cipher:
        secret = cipher.encrypt(json.dumps([[ip, login, fingerprint], password]).encode())
        db.execute("INSERT OR REPLACE INTO eeprom_credentials VALUES (?,?)", (ip, secret))
    db.execute("DELETE FROM metrics WHERE ip=?", (ip,))


def restore_reinstalled_ssh(database, cipher, device_lock):
    now = int(time.time())
    with sqlite3.connect(database) as db:
        pending = db.execute("""SELECT ip, login, secret, fingerprint FROM reinstall_ssh
                                WHERE expires > ? AND fingerprint IS NOT NULL""", (now,)).fetchall()
    for ip, login, secret, fingerprint in pending:
        with device_lock(ip):
            try:
                identity, password = json.loads(cipher.decrypt(secret))
                if identity != [ip, login]:
                    continue
                private = telemetry.enroll(ip, login, fingerprint, password)
            except (InvalidToken, OSError, ValueError, paramiko.SSHException):
                continue
            with sqlite3.connect(database) as db:
                if db.execute("DELETE FROM reinstall_ssh WHERE ip=? AND secret=?", (ip, secret)).rowcount:
                    save_ssh(db, ip, login, fingerprint, private, cipher, password)


def monitor(database, cipher, device_lock):
    while True:
        try:
            if cipher:
                restore_reinstalled_ssh(database, cipher, device_lock)
            sample_devices(database)
        except (sqlite3.Error, OSError) as error:
            print(f"Monitoring: {error}", flush=True)
        time.sleep(30)


def installation_status(database, ip, legacy_ip):
    with sqlite3.connect(database) as db:
        row = db.execute("SELECT ip,status FROM reinstall WHERE id=1").fetchone()
    if row:
        return STATES[row[1]] if row[0] == ip else None
    if ip != legacy_ip:
        return None
    directory = Path(database).with_name("jobs")
    try:
        latest = max(
            (entry for entry in directory.iterdir() if entry.suffix in {".pending", ".claimed", ".completed"}),
            key=lambda entry: entry.stat().st_mtime,
            default=None,
        )
    except OSError:
        return "Нет активного задания"
    if latest is None:
        return "Нет активного задания"
    if latest.suffix == ".pending":
        return "Установщик ожидает Pi"
    if latest.suffix == ".completed":
        return "Установка завершена, SSH доступен"
    return "Разрешение на запись выдано"


def render_metrics(samples):
    if not samples or time.time() - samples[0][0] > 120:
        return '<div class="metrics"><small>Метрики ожидают подключения по SSH</small></div>'
    at, ticks, idle, total, used, rx, tx, disk = samples[0]
    cpu, network = "—", "—"
    if len(samples) > 1:
        prior, old_ticks, old_idle, _, _, old_rx, old_tx, _ = samples[1]
        if ticks > old_ticks and idle >= old_idle:
            cpu = f"{max(0, min(100, 100 * (1 - (idle - old_idle) / (ticks - old_ticks)))):.0f}%"
        if at > prior and rx >= old_rx and tx >= old_tx:
            network = f"↓ {(rx - old_rx) / (at - prior) / 1024:.1f} · ↑ {(tx - old_tx) / (at - prior) / 1024:.1f} КиБ/с"
    fields = (("CPU", cpu), ("RAM", f"{used / 1048576:.1f} / {total / 1048576:.1f} ГиБ"),
              ("Сеть", network), ("Диск /", f"{disk}%"))
    return '<div class="metrics">' + "".join(f"<div><small>{label}</small><b>{value}</b></div>" for label, value in fields) + "</div>"



def render_charts(samples):
    if not samples:
        return '<div class="chart-grid"><small>Пока нет сохранённых измерений.</small></div>'
    columns = {"cpu": [], "ram": [], "disk": [], "rx": [], "tx": []}
    previous = None
    for row in reversed(samples):
        at, ticks, idle, total, used, rx, tx, disk = row
        columns["ram"].append((at, 100 * used / total if total else None))
        columns["disk"].append((at, disk))
        if previous:
            old_at, old_ticks, old_idle, _, _, old_rx, old_tx, _ = previous
            interval = at - old_at
            cpu = max(0, min(100, 100 * (1 - (idle - old_idle) / (ticks - old_ticks)))) if ticks > old_ticks and idle >= old_idle else None
            columns["cpu"].append((at, cpu if 0 < interval <= 240 else None))
            columns["rx"].append((at, (rx - old_rx) / interval / 1024 if 0 < interval <= 240 and rx >= old_rx else None))
            columns["tx"].append((at, (tx - old_tx) / interval / 1024 if 0 < interval <= 240 and tx >= old_tx else None))
        previous = row

    end = int(time.time())
    start = end - 86400

    def series(points, maximum, color):
        segments, current = [], []
        last = None
        for at, value in points:
            if value is None or (last is not None and at - last > 240):
                if current:
                    segments.append(current)
                current = []
            if value is not None:
                x = max(0, min(240, (at - start) / 360))
                y = 64 - max(0, min(1, value / maximum)) * 60
                current.append((x, y))
            last = at
        if current:
            segments.append(current)
        traces = []
        for segment in segments:
            if len(segment) == 1:
                x, y = segment[0]
                traces.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2" fill="{color}"/>')
            else:
                coordinates = " ".join(f"{x:.1f},{y:.1f}" for x, y in segment)
                traces.append(f'<polyline points="{coordinates}" stroke="{color}"/>')
        return "".join(traces)

    def chart(label, keys, maximum, unit):
        colors = ("#007d64", "#6847c1")
        traces = "".join(series(columns[key], maximum, color) for key, color in zip(keys, colors))
        return f"""<div class="chart"><div class="line"><b>{label}</b><small>0–{maximum:g} {unit}</small></div>
        <svg viewBox="0 0 240 68" preserveAspectRatio="none" role="img" aria-label="{label}, последние 24 часа">
          <line x1="0" x2="240" y1="4" y2="4"/><line x1="0" x2="240" y1="34" y2="34"/>
          <line x1="0" x2="240" y1="64" y2="64"/>{traces}
        </svg><div class="line"><small>−24 ч</small><small>сейчас</small></div></div>"""

    network_max = max([1] + [value for key in ("rx", "tx") for _, value in columns[key] if value is not None])
    return '<div class="chart-grid">' + "".join((
        chart("CPU", ("cpu",), 100, "%"),
        chart("RAM", ("ram",), 100, "%"),
        chart("Сеть · ↓ приём / ↑ передача", ("rx", "tx"), round(network_max + .05, 1), "КиБ/с"),
        chart("Диск /", ("disk",), 100, "%"),
    )) + "</div>"

def install_busy(database, ip=None, legacy_ip=None):
    with sqlite3.connect(database) as db:
        row = db.execute("SELECT ip,status FROM reinstall WHERE id=1").fetchone()
    if row:
        return (ip is None or row[0] == ip) and row[1] in ACTIVE
    if ip is not None and ip != legacy_ip:
        return False
    jobs = Path(database).with_name("jobs")
    if not jobs.exists():
        return False
    for entry in jobs.iterdir():
        if entry.suffix == ".pending":
            return True
        if entry.suffix == ".claimed":
            try:
                if time.time() - entry.stat().st_mtime < 1200:
                    return True
            except FileNotFoundError:
                continue
    return False


def render_power(server, ip, physical_port):
    if physical_port is None:
        return '<div class="job power"><b>Питание</b><span>Управляется вручную</span></div>'
    if ip not in server.switch.ports or server.switch.ports[ip][0] != physical_port:
        if server.admin and server.switch.allow_registration:
            return f"""
            <form class="power" method="post" action="/poe/register">
              <input type="hidden" name="ip" value="{ip}">
              <label class="confirm"><input type="checkbox" name="confirm" value="yes" required>
              Кабель этой Pi подключён к порту {physical_port}</label>
              <button class="secondary">Зарегистрировать PoE-порт</button>
            </form>"""
        return '<small>Управление PoE ожидает проверки порта.</small>'
    try:
        port, enabled, delivering = server.switch.status(ip)
    except (PoeError, KeyError):
        return '<div class="job power"><b>PoE</b><span>Коммутатор не ответил</span></div>'
    label = "Питание подаётся" if delivering else "Включено, без нагрузки" if enabled else "Выключено"
    controls = f"""
        <p><a class="button secondary" href="{server.admin_url}">
        Питание и настройки ОС</a></p>
        <small>Управление открывается по HTTPS.</small>"""
    if server.admin:
        blocked = install_busy(server.database, ip, server.test_pi)
        disabled = "disabled" if blocked or not server.switch.allow_write else ""
        hint = "Запись на SD активна" if blocked else "Доступ SNMP на запись ещё не включён" if disabled else ""
        controls = f"""
        <form method="post" action="/power">
          <input type="hidden" name="ip" value="{ip}">
          <label class="confirm"><input type="checkbox" name="confirm" value="yes" required>
          Подтверждаю изменение питания порта {port}</label>
          <button name="state" value="on" {disabled}>Вкл</button>
          <button name="state" value="off" {disabled}>Выкл</button>
          <button name="state" value="restart" {disabled}>Аппаратная перезагрузка</button>
          <small>{hint}</small>
        </form>"""
    return f'<div class="power"><div class="job power-status"><b>PoE · порт {port}</b><span>{label}</span></div>{controls}</div>'


def render_card(device, samples, metrics, history, installer, power, admin, ready_images, eeprom_key, has_eeprom_access, has_collector=True, provisioned=False, vnc_url="", network_defaults=None):
    ip, name, image, boot, physical_port, cid = device
    network_defaults = network_defaults or {}
    last = samples[0] if samples else None
    online = last and last[1]
    state = "SSH доступен" if online else "SSH недоступен" if last else "Ожидает проверки"
    checked = datetime.fromtimestamp(last[0]).astimezone().strftime("%H:%M:%S %Z") if last else "—"
    bars = "".join(
        f'<span class="{"good" if status else "bad"}" title="{datetime.fromtimestamp(at).astimezone():%d.%m %H:%M %Z} · {"доступен" if status else "недоступен"}"></span>'
        for at, status in reversed(samples)
    )
    status = f'<div class="job install-status"><b>Переустановка</b><span>{installer}</span></div>' if installer else ""
    available = {key: label for key, label in IMAGES.items() if key in ready_images}
    install = f"""
      <details><summary>Настройки новой ОС</summary>
        <form method="post" action="/reinstall">
          <label>Новая ОС<select name="image" required>{options(available, image)}</select></label>
          <input type="hidden" name="ip" value="{ip}">
          <label>Имя хоста<input name="hostname" required maxlength="63"></label>
          <label>Логин<input name="login" required maxlength="32"></label>
          <label>Пароль<input type="password" name="password" required minlength="8" maxlength="128" autocomplete="new-password"></label>
          <label>Сеть новой ОС<select name="network_mode"><option value="static" selected>Статический IP из карточки</option><option value="dhcp">DHCP</option></select></label>
          <fieldset data-static-network>
            <label>IP-адрес<input name="address" value="{ip}" readonly></label>
            <label>Префикс сети<input name="prefix" type="number" min="1" max="30" required value="{network_defaults.get('prefix',24)}"></label>
            <label>Шлюз<input name="gateway" required value="{escape(network_defaults.get('gateway',''),quote=True)}" placeholder="192.168.10.1"></label>
            <label>DNS (через пробел)<input name="dns" required value="{escape(network_defaults.get('dns',''),quote=True)}" placeholder="192.168.10.1"></label>
          </fieldset>
          <label class="confirm"><input type="checkbox" name="confirm" value="yes" required>
          Разрешаю стереть SD-карту {escape(name)} и перезапустить Pi</label>
          <button {"disabled" if not available else ""}>Переустановить ОС</button>
        </form>
      </details>""" if admin and ready_images else '<small>Для переустановки нужны зарегистрированная SD-карта и настроенный PoE.</small>' if admin else ""
    edit = f"""
      <details><summary>Редактировать карточку</summary>
        <form method="post" action="/devices/edit">
          <input type="hidden" name="ip" value="{ip}">
          <label>Имя<input name="name" required maxlength="60" value="{escape(name, quote=True)}"></label>
          <label>Порт коммутатора (необязательно)<input name="port" type="number" min="1" max="24" value="{physical_port or ''}"></label>
          <label>CID SD-карты (необязательно)<input name="cid" pattern="[a-fA-F0-9]{{32}}" maxlength="32" value="{cid or ''}"></label>
          <label>Адрес VNC / веб-консоли (необязательно)<input name="vnc_url" maxlength="512" value="{escape(vnc_url, quote=True)}" placeholder="vnc://{ip}:5900 или https://…"></label>
          <button>Сохранить карточку</button>
        </form>
      </details>""" if admin else ""
    access_fields = '<label>SSH-логин<input name="login" maxlength="32" autocomplete="username"></label><label>Новый отпечаток SSH<input name="fingerprint" placeholder="SHA256:…"></label>'
    ssh_access = f'''<details><summary>Доступ SSH и метрики</summary>
      <p>При смене ОС укажите текущие данные SSH. Если логин и отпечаток прежние, достаточно пароля.</p>
      <form method="post" action="/devices/access"><input type="hidden" name="ip" value="{ip}">
      {access_fields}<label>Пароль SSH<input type="password" name="password" required maxlength="256" autocomplete="current-password"></label>
      <button>Сохранить доступ</button></form></details>''' if admin else ""
    boot_choices = {key: label for key, (label, _) in eeprom.BOOT_ORDERS.items()}
    firmware = f"""
      <details><summary>Настроить EEPROM</summary>
        <p>Для переустановки из Pi Fleet выбери «Сеть HTTP → SD». При загрузке с SD или USB в первую очередь исправная ОС может запуститься раньше сетевого установщика.</p>
        <form method="post" action="/eeprom">
          <input type="hidden" name="ip" value="{ip}">
          <button class="secondary" formaction="/eeprom/read" formnovalidate>Показать текущие настройки</button>
          <label>Новый порядок загрузки<select name="profile">{options(boot_choices, "http-sd")}</select></label>
          <label class="confirm"><input type="checkbox" name="confirm" value="yes" required>
          Применить выбранный порядок загрузки и перезагрузить Pi</label>
          <button>Настроить EEPROM и перезагрузить</button>
        </form>
      </details>""" if admin and eeprom_key and has_eeprom_access else ""
    setup = f"""
      <form method="post" action="/provision/check">
        <input type="hidden" name="ip" value="{ip}">
        <button class="secondary">Проверить готовность к переустановке</button>
      </form>""" if admin and has_eeprom_access and not provisioned else ""
    vnc_setup = f"""
      <details><summary>Установить VNC</summary>
        <p>Доступ к настоящей локальной консоли tty1, без рабочего стола. При запуске включается tty1 на мониторе Pi; ввод общий с локальной клавиатурой. Для установки используется SSH этой карточки с sudo. Установка может занять несколько минут.</p>
        <form method="post" action="/vnc/install">
          <input type="hidden" name="ip" value="{ip}">
          <label>Отдельный пароль VNC (ровно 8 символов)<input type="password" name="vnc_password" required minlength="8" maxlength="8" pattern="[!-~]{{8}}" autocomplete="new-password"></label>
          <label class="confirm"><input type="checkbox" name="confirm" value="yes" required>Установить VNC локальной консоли с управлением клавиатурой и автозапуском на порту 5909</label>
          <button>Установить VNC</button>
        </form>
      </details>""" if admin and has_eeprom_access else ""
    dialog_id = "settings-" + ip.replace(".", "-")
    install_id = "install-" + ip.replace(".", "-")
    install_form = install.replace('<details><summary>Настройки новой ОС</summary>', '').replace('</details>', '')
    install_action = f'<button data-dialog="{install_id}">Переустановить ОС</button>' if admin and ready_images else ''
    install_dialog = f'<dialog id="{install_id}" class="device-dialog"><div class="dialog-head"><div><h2>Переустановка ОС</h2><small>{escape(name)} · {ip}</small></div><button class="secondary" data-close-dialog aria-label="Закрыть">×</button></div>{install_form}</dialog>' if admin and ready_images else ''
    return f"""
      <article data-device="{ip}"><div class="card-head"><div class="device-icon" aria-hidden="true">Pi</div>
      <div class="identity"><h3>{escape(name)}</h3><code>{ip}{f" · порт {physical_port}" if physical_port is not None else ""}</code></div>
      <span class="badge {'up' if online else 'down' if last else ''}">{state}</span></div>
      <div class="health"><div class="line"><b>История SSH</b><span>{checked}</span></div>
      <div class="bars" aria-label="Последние проверки SSH">{bars or '<small>Пока нет данных</small>'}</div></div>
      {render_metrics(metrics)}
      {status}
      {power}
      <div class="card-actions">{install_action}
        <a class="button secondary" href="{escape(vnc_url or 'vnc://' + ip + ':5900', quote=True)}" target="_blank" rel="noopener noreferrer">Консоль VNC</a>
        <button class="secondary" data-dialog="{dialog_id}">Настройки</button>
      </div>
      <dialog id="{dialog_id}" class="device-dialog">
        <div class="dialog-head"><div><h2>Настройки</h2><small>{escape(name)} · {ip}</small></div><button class="secondary" data-close-dialog aria-label="Закрыть">×</button></div>
        <details><summary>История метрик · 24 часа</summary>{render_charts(history)}</details>
        {edit}{ssh_access}{firmware}{setup}{vnc_setup}{install if not ready_images else ''}
        <p class="console-hint">VNC Pi Fleet — настоящая локальная tty1, порт 5909. Нужен клиент с TLS/VeNCrypt. Для доступа до загрузки Linux используйте BliKVM.</p>
      </dialog>{install_dialog}</article>"""


class HTTPSRedirect(BaseHTTPRequestHandler):
    def redirect_to_https(self, status):
        path = self.path
        if not path.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in path):
            path = "/"
        self.send_response(status)
        self.send_header("Location", self.server.admin_url.rstrip("/") + path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.redirect_to_https(308)

    do_HEAD = do_GET

    def do_POST(self):
        self.redirect_to_https(303)


class Panel(BaseHTTPRequestHandler):
    def authorized(self):
        if not self.server.auth_digest:
            return True
        try:
            scheme, token = self.headers.get("Authorization", "").split(" ", 1)
            credential = base64.b64decode(token, validate=True)
            digest = hashlib.sha256(credential).hexdigest()
            if scheme.lower() == "basic" and hmac.compare_digest(digest, self.server.auth_digest):
                return True
        except ValueError:
            pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Pi Fleet"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_GET(self):
        if self.path == "/favicon.png":
            icon = Path(__file__).with_name("favicon.png").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(icon)))
            self.end_headers()
            self.wfile.write(icon)
            return
        if not self.authorized():
            return
        if self.path == "/pi-fleet-ca.crt" and self.server.ca_path:
            body = self.server.ca_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/":
            self.send_error(404)
            return
        with sqlite3.connect(self.server.database) as db:
            devices = db.execute("SELECT ip, name, image, boot, physical_port, sd_cid FROM devices ORDER BY name, ip").fetchall()
            samples = {
                ip: db.execute("SELECT checked, online FROM samples WHERE ip=? ORDER BY checked DESC LIMIT 24", (ip,)).fetchall()
                for ip, *_ in devices
            }
            metrics = {
                ip: db.execute("SELECT checked, ticks, idle, mem, used, rx, tx, disk FROM metrics WHERE ip=? ORDER BY checked DESC LIMIT 2", (ip,)).fetchall()
                for ip, *_ in devices
            }
            history = {
                ip: db.execute(
                    "SELECT checked,ticks,idle,mem,used,rx,tx,disk FROM metrics "
                    "WHERE ip=? AND checked IN (SELECT max(checked) FROM metrics WHERE ip=? AND checked>=? GROUP BY checked / 120) "
                    "ORDER BY checked DESC",
                    (ip, ip, int(time.time()) - 86400),
                ).fetchall()
                for ip, *_ in devices
            }
            collector_devices = {row[0] for row in db.execute("SELECT ip FROM collectors")}
            reinstall_networks = load_reinstall_networks(db, self.server.network)
            provisioned_devices = {row[0] for row in db.execute("SELECT ip FROM provisioning")}
            consoles = dict(db.execute("SELECT ip,url FROM consoles"))
            eeprom_devices = {row[0] for row in db.execute("SELECT ip FROM eeprom_credentials")}
        up = sum(bool(history and history[0][1]) for history in samples.values())
        down = sum(bool(history and not history[0][1]) for history in samples.values())
        defaults_file = self.server.switch.directory / "network-defaults.json"
        network_defaults = {"prefix": self.server.network.prefixlen}
        if defaults_file.is_file():
            network_defaults.update(json.loads(defaults_file.read_text()))
        def device_network_defaults(ip):
            profile = reinstall_profile(ip, self.server.network, reinstall_networks)
            if profile and profile[1]:
                subnet, gateway = profile
                return {"prefix": subnet.prefixlen, "gateway": str(gateway), "dns": str(gateway)}
            return network_defaults

        rows = "".join(
            render_card(device, samples[device[0]], metrics[device[0]], history[device[0]], installation_status(self.server.database, device[0], self.server.test_pi), render_power(self.server, device[0], device[4]), self.server.admin, self.ready_images(device[0]) if device[4] is not None and device[5] and self.server.switch.ports.get(device[0], (None,))[0] == device[4] and self.server.switch.allow_write else set(), self.eeprom_key().is_file(), bool(self.server.credential_cipher and device[0] in eeprom_devices), device[0] in collector_devices, device[0] in provisioned_devices, consoles.get(device[0], ""), device_network_defaults(device[0]))
            for device in devices
        )
        enroll_fields = """
        <label>SSH-логин<input name="login" autocomplete="username" placeholder="mortal"></label>
        <label>Пароль SSH<input type="password" name="password" autocomplete="current-password"></label>
        <label class="wide">Отпечаток ключа Pi<input name="fingerprint" placeholder="SHA256:…"></label>
        <small class="wide">Для сбора метрик заполните все три поля SSH. Для карточки без метрик оставьте их пустыми.</small>
        """ if self.server.admin else ""
        if self.server.admin and self.server.credential_cipher:
            enroll_fields += """
            <small class="wide">Данные SSH сохраняются для управления этой Pi. Пароль хранится зашифрованным; для настройки EEPROM пользователю нужны права sudo.</small>
            """
        action = "/devices"
        label = "Добавить"
        hint = "" if self.server.admin else "<p>Для подключения метрик откройте защищённую панель по HTTPS.</p>"
        network_button = '<button class="secondary" data-dialog="reinstall-networks">Сети переустановки</button>' if self.server.admin else ""
        network_lines = "\n".join(f"{network} {gateway}" for network, gateway in reinstall_networks.items())
        network_dialog = f'''<dialog id="reinstall-networks" class="device-dialog">
        <div class="dialog-head"><h2>Сети переустановки</h2><button class="secondary" data-close-dialog aria-label="Закрыть">×</button></div>
        <p>Основная сеть {self.server.network} включена всегда. Для каждой дополнительной сети укажите CIDR и шлюз через пробел. Из этой сети Raspberry Pi должна видеть загрузочный сервер на TCP 8083.</p>
        <form method="post" action="/reinstall-networks">
        <label>Дополнительные сети<textarea name="networks" rows="5" maxlength="800" placeholder="192.168.89.0/24 192.168.89.1">{escape(network_lines)}</textarea></label>
        <button>Сохранить</button></form></dialog>''' if self.server.admin else ""
        html = f"""<!doctype html>
        <html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Pi Fleet · Устройства</title><link rel="icon" href="/favicon.png" type="image/png" sizes="32x32"><style>{DASHBOARD_CSS}</style><nav><div><strong>Pi Fleet</strong><span>Локальная сеть · Raspberry Pi</span>{network_button}<button data-dialog="add-device">+ Добавить Pi</button></div></nav>
        <main><header><small>УПРАВЛЕНИЕ RASPBERRY PI</small>
        <h1>Устройства</h1><p>Состояние, сетевой запуск и параметры переустановки.</p></header>
        <div class="stats"><div><small>Всего Pi</small><strong>{len(devices)}</strong></div>
        <div><small>SSH доступен</small><strong>{up}</strong></div><div><small>SSH недоступен</small><strong>{down}</strong></div></div>
        <div class="section"><h2>Парк устройств</h2><div class="tools">
        <input type="search" id="device-filter" placeholder="Имя, IP или порт" aria-label="Фильтр устройств">
        </div></div>
        <div class="grid">{rows or '<p>Устройства ещё не добавлены.</p>'}</div>
        <dialog id="add-device" class="device-dialog add-device-dialog"><div class="dialog-head"><div><h2>Добавить Raspberry Pi</h2><small>Устройство, сеть и доступ SSH</small></div><button class="secondary" data-close-dialog aria-label="Закрыть">×</button></div>{hint}<form class="add-device-form" method="post" action="{action}">
        <label>Имя<input name="name" required maxlength="60" placeholder="pi-lab-02"></label>
        <label>IPv4<input name="ip" required placeholder="192.168.10.250"></label>
        <label>Порт коммутатора (необязательно)<input name="port" type="number" min="1" max="24" step="1" placeholder="19"></label>
        {('<label>CID SD-карты (необязательно)<input name="cid" pattern="[a-fA-F0-9]{32}" maxlength="32"></label><small>На Pi: cat /sys/block/mmcblk0/device/cid</small>') if self.server.admin else ""}
        {enroll_fields}
        <button>{label}</button>
        </form></dialog>{network_dialog}
        <footer>Проверка SSH каждые 30 секунд. Состояние обновляется автоматически. Переустановка доступна для зарегистрированной SD-карты.</footer></main>
        <dialog id="action-result" aria-labelledby="action-result-title">
          <h2 id="action-result-title"></h2><p id="action-result-message"></p>
          <form method="dialog"><button autofocus>Закрыть</button></form>
        </dialog>
        <script>
        document.addEventListener("click", event => {{
          const opener = event.target.closest("[data-dialog]");
          if (opener) {{
            const dialog = document.getElementById(opener.dataset.dialog);
            if (dialog && !dialog.open) dialog.showModal();
          }}
          const closer = event.target.closest("[data-close-dialog]");
          if (closer) closer.closest("dialog").close();
        }});
        if (location.hash === "#add-device") document.getElementById("add-device").showModal();
        const result = document.querySelector("#action-result");
        function showResult(title, message) {{
          result.querySelector("h2").textContent = title;
          result.querySelector("p").textContent = message;
          if (!result.open) result.showModal();
        }}
        document.addEventListener("submit", async (event) => {{
          const form = event.target;
          if (!["/devices", "/reinstall-networks", "/eeprom", "/provision/check", "/devices/access", "/vnc/install"].includes(form.getAttribute("action"))) return;
          event.preventDefault();
          const button = event.submitter || form.querySelector('button:not([formaction])');
          const action = button.getAttribute("formaction") || form.getAttribute("action");
          const installingVnc = action === "/vnc/install";
          const reading = action === "/eeprom/read";
          const savingAccess = action === "/devices/access";
          const checking = action === "/provision/check";
          if (form.dataset.busy) return;
          form.dataset.busy = "yes";
          const label = button.textContent;
          button.disabled = true;
          button.textContent = action === "/devices" ? "Добавляем Pi…" : action === "/reinstall-networks" ? "Сохраняем сети…" : installingVnc ? "Устанавливаем VNC…" : savingAccess ? "Сохраняем доступ…" : reading ? "Читаем настройки…" : checking ? "Проверяем Pi…" : "Подготавливаем EEPROM…";
          try {{
            const response = await fetch(action, {{
              method: "POST", body: new URLSearchParams(new FormData(form)), cache: "no-store",
            }});
            if (["/devices", "/reinstall-networks"].includes(action) && response.redirected && response.ok) {{
              location.assign(response.url);
              return;
            }}
            const body = await response.text();
            if (response.ok) {{
              if (!reading && !checking && !savingAccess && !installingVnc) {{
                form.querySelector('input[name="confirm"]').checked = false;
              }}
              showResult(installingVnc ? "VNC установлен" : savingAccess ? "Доступ сохранён" : reading ? "Текущие настройки загрузчика" : checking ? "Pi готова к переустановке" : "Перезагрузка запланирована", body);
              if (checking || savingAccess || installingVnc) result.addEventListener("close", () => location.reload(), {{once:true}});
            }} else {{
              const paragraphs = new DOMParser().parseFromString(body, "text/html").querySelectorAll("p");
              const message = paragraphs.length ? paragraphs[paragraphs.length - 1].textContent : body;
              showResult("Не удалось завершить настройку", message.replace(/^Error code explanation:\\s*\\d+\\s*-\\s*/, ""));
            }}
          }} catch {{
            showResult("Связь с панелью прервалась", "Проверьте состояние Pi перед повторной отправкой.");
          }} finally {{
            delete form.dataset.busy;
            button.disabled = false;
            button.textContent = label;
          }}
        }});
        document.addEventListener("change", event => {{
          if (event.target.name === "network_mode") {{
            event.target.form.querySelector("[data-static-network]").disabled = event.target.value !== "static";
          }}
        }});
        const filter = document.querySelector("#device-filter");
        filter.addEventListener("input", () => {{
          const query = filter.value.trim().toLowerCase();
          for (const card of document.querySelectorAll("[data-device]")) {{
            card.hidden = !card.querySelector(".identity").textContent.toLowerCase().includes(query);
          }}
        }});
        const refresh = async () => {{
          if (document.hidden) return;
          try {{
            const response = await fetch("/", {{cache: "no-store"}});
            if (!response.ok) return;
            const next = new DOMParser().parseFromString(await response.text(), "text/html");
            document.querySelector(".stats").replaceChildren(...next.querySelector(".stats").children);
            for (const card of document.querySelectorAll("[data-device]")) {{
              const updated = next.querySelector(`[data-device="${{card.dataset.device}}"]`);
              if (!updated) continue;
              for (const part of [".badge", ".health", ".metrics", ".chart-grid", ".install-status", ".power-status"]) {{
                const current = card.querySelector(part);
                const replacement = updated.querySelector(part);
                if (current && replacement) current.replaceWith(replacement);
              }}
            }}
          }} catch {{ /* Keep showing the last recorded state. */ }}
        }};
        setInterval(refresh, 15000);
        </script></html>"""
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def register_poe(self, ip, data):
        switch = self.server.switch
        if not self.server.admin or not switch.allow_registration:
            self.send_error(404)
            return
        if data["confirm"][0] != "yes":
            raise ValueError
        with self.server.device_lock(ip), sqlite3.connect(self.server.database) as db:
            row = db.execute("SELECT physical_port FROM devices WHERE ip=?", (ip,)).fetchone()
            if not row or row[0] is None:
                self.send_error(409, "Set the physical switch port on the card first")
                return
            port = row[0]
            if install_busy(self.server.database, ip, self.server.test_pi):
                self.send_error(409, "An installation is already active")
                return
            existing = switch.ports.get(ip)
            if existing and existing[0] == port:
                self.redirect()
                return
            if existing or any(number == port or index == f".1.{port}"
                               for number, index in tuple(switch.ports.values())):
                self.send_error(409, "Port conflicts with an existing PoE mapping")
                return
            try:
                mapping = switch.verify_registration(port)
            except PoeError:
                self.send_error(502, "PoE verification failed",
                                f"Check SNMP read and Write View for 1.3.6.1.2.1.105.1.1.1.3.1.{port}")
                return
            with self.server.mapping_lock:
                db.execute("INSERT INTO poe_registrations VALUES (?,?,?)", (ip, port, switch.target))
                db.commit()
                switch.ports[ip] = mapping
        self.redirect()

    def eeprom_key(self):
        return self.server.switch.directory / "eeprom-public.pem"

    def do_eeprom(self, ip, data):
        installing_vnc = self.path == "/vnc/install"
        if not self.server.admin or (not installing_vnc and not self.eeprom_key().is_file()):
            self.send_error(404)
            return
        reading = self.path == "/eeprom/read"
        checking = self.path == "/provision/check"
        profile = data.get("profile", ["http-sd"])[0]
        if not reading and not checking and not installing_vnc and (data["confirm"][0] != "yes" or profile not in eeprom.BOOT_ORDERS):
            raise ValueError
        with self.server.device_lock(ip):
            if not reading and install_busy(self.server.database, ip, self.server.test_pi):
                self.send_error(409, "An installation is already active")
                return
            with sqlite3.connect(self.server.database) as db:
                row = db.execute(
                    "SELECT c.login,c.fingerprint,e.secret FROM collectors c "
                    "JOIN eeprom_credentials e USING(ip) JOIN devices d USING(ip) WHERE ip=?", (ip,),
                ).fetchone()
            if not row or not self.server.credential_cipher:
                self.send_error(409, "SSH access is missing",
                                "Сохраните пароль в разделе доступа SSH этой карточки.")
                return
            login, fingerprint, token = row
            try:
                identity, password = json.loads(self.server.credential_cipher.decrypt(token))
                if identity != [ip, login, fingerprint]:
                    raise ValueError
            except (InvalidToken, ValueError):
                self.send_error(409, "SSH credentials must be renewed",
                                "Повторно подключите SSH-доступ для EEPROM.")
                return
            try:
                if installing_vnc:
                    if data.get("confirm", [""])[0] != "yes":
                        raise ValueError("Подтвердите установку VNC.")
                    vnc.install(ip, login, fingerprint, password, data.get("vnc_password", [""])[0])
                    with sqlite3.connect(self.server.database) as db:
                        db.execute("INSERT OR REPLACE INTO consoles VALUES (?,?)", (ip, f"vnc://{ip}:{vnc.PORT}"))
                    output = f"VNC локальной консоли tty1 установлен: {ip}:{vnc.PORT}. Автозапуск включён. Пароль — тот, который вы указали в форме. Откройте VNC-клиент с поддержкой TLS/VeNCrypt, например TigerVNC. Это общий экран tty1 и общая клавиатура с подключённым монитором. Пока ОС не запущена, программный VNC недоступен; для EEPROM и аварийной загрузки используйте BliKVM. Если на Pi включён межсетевой экран, разрешите доступ к TCP {vnc.PORT} из вашей сети."
                elif checking:
                    cid, mac, budget = eeprom.provisioning_identity(
                        ip, login, fingerprint, password, getattr(self.server,"boot_host",urlsplit(self.server.origin).hostname),
                    )
                    with sqlite3.connect(self.server.database) as db:
                        port, saved_cid = db.execute("SELECT physical_port,sd_cid FROM devices WHERE ip=?", (ip,)).fetchone()
                        mapping = self.server.switch.ports.get(ip)
                        if not self.server.switch.allow_write or not mapping or mapping[0] != port:
                            raise ValueError("Сначала зарегистрируйте PoE-порт в карточке.")
                        if saved_cid and saved_cid != cid:
                            raise ValueError("CID в карточке отличается от вставленной SD-карты.")
                        db.execute("UPDATE devices SET sd_cid=? WHERE ip=?", (cid, ip))
                        db.execute("INSERT OR REPLACE INTO provisioning VALUES (?,?,?)", (ip, mac, budget))
                    output = "Проверены Ethernet, настройки загрузчика, SD-карта и привязка PoE. Обновите карточку, чтобы выбрать ОС."
                elif reading:
                    output = eeprom.read_settings(ip, login, fingerprint, password)
                else:
                    eeprom.stage(ip, login, fingerprint, password,
                                 getattr(self.server,"boot_host",urlsplit(self.server.origin).hostname), self.eeprom_key(), profile)
                    with sqlite3.connect(self.server.database) as db:
                        db.execute("DELETE FROM provisioning WHERE ip=?", (ip,))
                    label = eeprom.BOOT_ORDERS[profile][0]
                    output = f"Порядок «{label}» подготовлен. Pi перезагрузится примерно через 10 секунд."
            except ValueError as error:
                self.send_error(422, "Device configuration check failed", str(error))
                return
            except (OSError, paramiko.SSHException) as error:
                reason = str(error)
                if reason not in (*eeprom.ERRORS.values(), *vnc.ERRORS.values()):
                    reason = "Проверьте SSH, отпечаток, пароль и права sudo."
                self.send_error(422, "VNC installation failed" if installing_vnc else "EEPROM preparation failed", reason)
                return
        body = output.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def ready_images(self, ip):
        with sqlite3.connect(self.server.database) as db:
            profiles = load_reinstall_networks(db, self.server.network)
        if not reinstall_profile(ip, self.server.network, profiles):
            return set()
        if ip != self.server.test_pi:
            with sqlite3.connect(self.server.database) as db:
                if not db.execute("SELECT 1 FROM provisioning WHERE ip=?", (ip,)).fetchone():
                    return set()
        directory = self.server.switch.directory
        return {image for image in IMAGES if (directory / (image + ".ready")).is_file()}

    def do_POST(self):
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin", "")
        allowed = getattr(self.server, "allowed_origins", (self.server.origin,))
        if origin not in allowed or host != urlsplit(origin).netloc:
            self.send_error(403)
            return
        if not self.authorized():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError
            data = parse_qs(self.rfile.read(length).decode(), max_num_fields=20)
            if self.path == "/reinstall-networks":
                self.save_reinstall_networks(data.get("networks", [""])[0])
                return
            with sqlite3.connect(self.server.database) as db:
                profiles = load_reinstall_networks(db, self.server.network)
            try:
                ip = ipaddress.IPv4Address(data["ip"][0].strip())
            except (KeyError, ValueError):
                self.send_error(400, "Invalid IPv4 address", "Укажите корректный IPv4-адрес устройства.")
                return
            networks = (self.server.network, *getattr(self.server, "management_networks", ()), *profiles)
            if not any(ip in network and ip not in (network.network_address, network.broadcast_address)
                       for network in networks):
                self.send_error(400, "Address outside fleet networks",
                                "Разрешённые подсети: " + ", ".join(map(str, networks)))
                return
            if (self.path in ("/reinstall", "/provision/check", "/eeprom")
                    and not reinstall_profile(ip, self.server.network, profiles)):
                self.send_error(422, "Boot network required",
                                "Добавьте подсеть Pi в разделе «Сети переустановки».")
                return
            if self.path == "/poe/register":
                self.register_poe(str(ip), data)
                return
            if self.path == "/devices/access":
                if not self.server.admin or not self.server.credential_cipher:
                    self.send_error(404)
                    return
                password = data["password"][0]
                if not password or len(password) > 256 or any(c in password for c in "\r\n\0"):
                    raise ValueError
                with self.server.device_lock(str(ip)):
                    with sqlite3.connect(self.server.database) as db:
                        if not db.execute("SELECT 1 FROM devices WHERE ip=?", (str(ip),)).fetchone():
                            self.send_error(404)
                            return
                        row = db.execute("SELECT c.login,c.fingerprint FROM collectors c JOIN devices d USING(ip) WHERE ip=?", (str(ip),)).fetchone()
                    if install_busy(self.server.database, str(ip), self.server.test_pi):
                        self.send_error(409, "An installation is already active")
                        return
                    login = data.get("login", [""])[0].strip() or (row[0] if row else "")
                    fingerprint = submitted_fingerprint(data) or (row[1] if row else "")
                    if not valid_ssh(login, fingerprint, password):
                        self.send_error(422, "SSH data missing", "Проверьте логин, пароль и отпечаток текущей ОС.")
                        return
                    private = telemetry.enroll(str(ip), login, fingerprint, password)
                    with sqlite3.connect(self.server.database) as db:
                        save_ssh(db, str(ip), login, fingerprint, private, self.server.credential_cipher, password)
                        db.execute("DELETE FROM reinstall_ssh WHERE ip=?", (str(ip),))
                body = "Доступ сохранён в существующей карточке. Метрики обновятся в течение 30 секунд.".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path in ("/eeprom", "/eeprom/read", "/provision/check", "/vnc/install"):
                self.do_eeprom(str(ip), data)
                return
            if self.path in ("/devices", "/enroll", "/devices/edit"):
                port_text = data.get("port", [""])[0]
                port = int(port_text) if port_text else None
                cid = data.get("cid", [""])[0].strip().lower() or None
                if port is not None and not 1 <= port <= 24:
                    self.send_error(400, "Invalid switch port", "Укажите номер порта от 1 до 24.")
                    return
                if cid is not None and (not self.server.admin or not re.fullmatch(r"[0-9a-f]{32}", cid)):
                    self.send_error(400, "Invalid SD CID", "CID карты должен состоять из 32 шестнадцатеричных символов.")
                    return
                with sqlite3.connect(self.server.database) as db:
                    owner = db.execute("SELECT ip FROM devices WHERE physical_port=?", (port,)).fetchone()
                    if owner and owner[0] != str(ip):
                        self.send_error(409, "Switch port already assigned")
                        return
            if self.path == "/devices/edit":
                if not self.server.admin:
                    self.send_error(404)
                    return
                name = data["name"][0].strip()
                vnc_url = data.get("vnc_url", [""])[0].strip()
                parsed = urlsplit(vnc_url)
                if vnc_url and (len(vnc_url) > 512 or parsed.scheme not in ("http", "https", "vnc") or not parsed.hostname or parsed.username or parsed.password or any(ord(c) < 32 for c in vnc_url)):
                    raise ValueError
                if not 0 < len(name) <= 60:
                    raise ValueError
                with self.server.device_lock(str(ip)), self.server.mapping_lock, sqlite3.connect(self.server.database) as db:
                    if install_busy(self.server.database, str(ip), self.server.test_pi):
                        self.send_error(409, "An installation is already active")
                        return
                    registration = db.execute("SELECT port FROM poe_registrations WHERE ip=?", (str(ip),)).fetchone()
                    if not db.execute("UPDATE devices SET name=?, physical_port=?, sd_cid=? WHERE ip=?",
                                      (name, port, cid, str(ip))).rowcount:
                        self.send_error(404)
                        return
                    db.execute("INSERT OR REPLACE INTO consoles VALUES (?,?)", (str(ip), vnc_url))
                    if registration and registration[0] != port:
                        db.execute("DELETE FROM poe_registrations WHERE ip=?", (str(ip),))
                        db.commit()
                        if str(ip) not in self.server.static_ports:
                            self.server.switch.ports.pop(str(ip), None)
                self.redirect()
                return
            if self.path == "/power":
                if not self.server.admin:
                    self.send_error(404)
                    return
                requested = data["state"][0]
                if data["confirm"][0] != "yes" or requested not in ("on", "off", "restart"):
                    raise ValueError
                with self.server.device_lock(str(ip)):
                    with sqlite3.connect(self.server.database) as db:
                        port = db.execute("SELECT physical_port FROM devices WHERE ip=?", (str(ip),)).fetchone()
                    mapping = self.server.switch.ports.get(str(ip))
                    if not port or not mapping or port[0] != mapping[0]:
                        self.send_error(409, "Device port does not match the verified PoE mapping")
                        return
                    if install_busy(self.server.database, str(ip), self.server.test_pi):
                        self.send_error(409, "An installation is active on this Pi")
                        return
                    if requested == "restart":
                        self.server.switch.restart(str(ip))
                    else:
                        self.server.switch.set_power(str(ip), requested == "on")
                self.redirect()
                return
            if self.path in ("/install-config", "/reinstall"):
                if not self.server.admin:
                    self.send_error(404)
                    return
                hostname, login, password = (data[key][0] for key in ("hostname", "login", "password"))
                if (not valid_account(hostname, login) or not 8 <= len(password) <= 128
                        or any(ord(char) < 32 for char in password)):
                    raise ValueError
                with sqlite3.connect(self.server.database) as db:
                    if not db.execute("SELECT 1 FROM devices WHERE ip=?", (str(ip),)).fetchone():
                        self.send_error(404)
                        return
                hashed = subprocess.run(["openssl", "passwd", "-6", "-stdin"],
                                        input=password + "\n", text=True, capture_output=True,
                                        check=True, timeout=5).stdout.strip()
                if self.path == "/reinstall":
                    image = data["image"][0]
                    network = installation_network(str(ip), data.get("network_mode", ["dhcp"])[0],
                        data.get("address", [""])[0], data.get("prefix", ["24"])[0],
                        data.get("gateway", [""])[0], data.get("dns", [""])[0])
                    if image not in self.ready_images(str(ip)) or data["confirm"][0] != "yes":
                        raise ValueError
                    with self.server.device_lock(str(ip)):
                        if install_busy(self.server.database):
                            self.send_error(409, "An installation is already active")
                            return
                        with sqlite3.connect(self.server.database) as db:
                            db.execute("BEGIN IMMEDIATE")
                            active = db.execute("SELECT status FROM reinstall WHERE id=1").fetchone()
                            if active and active[0] in ACTIVE:
                                self.send_error(409, "An installation is already active")
                                return
                            if not reinstall_profile(ip, self.server.network,
                                                     load_reinstall_networks(db, self.server.network)):
                                self.send_error(422, "Boot network required", "Подсеть Pi не разрешена для переустановки.")
                                return
                            device = db.execute("SELECT physical_port, sd_cid FROM devices WHERE ip=?", (str(ip),)).fetchone()
                            mapping = self.server.switch.ports.get(str(ip))
                            if not device or not device[1] or not self.server.switch.allow_write or not mapping or device[0] != mapping[0]:
                                self.send_error(409, "Register the SD card and verify the PoE port first")
                                return
                            db.execute("INSERT OR REPLACE INTO reinstall (id,ip,image,hostname,login,password_hash,status,network_json) VALUES (1, ?, ?, ?, ?, ?, 'queued', ?)",
                                       (str(ip), image, hostname, login, hashed, json.dumps(network)))
                            db.execute("DELETE FROM reinstall_ssh WHERE ip=?", (str(ip),))
                            if self.server.credential_cipher and ip in self.server.network:
                                registered = db.execute("SELECT mac FROM provisioning WHERE ip=?", (str(ip),)).fetchone()
                                if not registered and str(ip) == self.server.test_pi:
                                    seed = self.server.switch.directory / "install-device.json"
                                    if seed.is_file():
                                        registered = (json.loads(seed.read_text())["mac"],)
                                if registered:
                                    secret = self.server.credential_cipher.encrypt(
                                        json.dumps([[str(ip), login], password]).encode())
                                    db.execute("INSERT INTO reinstall_ssh (ip,login,secret,mac) VALUES (?,?,?,?)",
                                               (str(ip), login, secret, registered[0]))
                    self.redirect()
                    return
                body = cloud_config("raspios-lite-arm64", hostname, login, hashed).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="user-data"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path in ("/devices", "/enroll"):
                self.add_device(str(ip), data, port, cid)
                return
            with sqlite3.connect(self.server.database) as db:
                if self.path == "/preferences":
                    image, boot = data["image"][0], data["boot"][0]
                    if image not in IMAGES or boot not in BOOT:
                        raise ValueError
                    if not db.execute("UPDATE devices SET image=?, boot=? WHERE ip=?", (image, boot, str(ip))).rowcount:
                        self.send_error(404)
                        return
                else:
                    self.send_error(404)
                    return
        except subprocess.SubprocessError:
            self.send_error(500, "Could not generate password hash")
            return
        except PoeError:
            self.send_error(502, "Switch did not confirm the PoE operation")
            return
        except (OSError, paramiko.SSHException):
            self.send_error(422, "SSH enrollment failed", "Не удалось подключиться по SSH. Проверьте адрес, логин, пароль и отпечаток текущей ОС.")
            return
        except (KeyError, ValueError):
            self.send_error(400, "Invalid device or preferences")
            return
        except sqlite3.IntegrityError:
            self.send_error(409, "Device already registered")
            return
        self.redirect()

    def save_reinstall_networks(self, value):
        if not self.server.admin:
            self.send_error(404)
            return
        try:
            profiles = parse_reinstall_networks(value, self.server.network)
        except ValueError as error:
            self.send_error(400, "Invalid installation networks", str(error))
            return
        with sqlite3.connect(self.server.database) as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("SELECT status FROM reinstall WHERE id=1").fetchone()
            if active and active[0] in ACTIVE:
                self.send_error(409, "Installation active", "Дождитесь завершения переустановки перед изменением сетей.")
                return
            db.execute("DELETE FROM reinstall_networks")
            db.executemany("INSERT INTO reinstall_networks VALUES (?,?)",
                           [(str(network), str(gateway)) for network, gateway in profiles.items()])
        self.redirect()

    def add_device(self, ip, data, port, cid):
        name = data.get("name", [""])[0].strip()
        login = data.get("login", [""])[0].strip()
        fingerprint = submitted_fingerprint(data)
        password = data.get("password", [""])[0]
        if not 0 < len(name) <= 60:
            self.send_error(400, "Invalid name", "Введите имя устройства длиной до 60 символов.")
            return
        enroll = bool(login or fingerprint or password)
        if enroll and (not self.server.admin or not valid_ssh(login, fingerprint, password)):
            self.send_error(400, "Incomplete SSH settings",
                            "Заполните SSH-логин, пароль и отпечаток формата SHA256:… или оставьте все три поля пустыми.")
            return
        with self.server.device_lock(ip):
            with sqlite3.connect(self.server.database) as db:
                if db.execute("SELECT 1 FROM devices WHERE ip=?", (ip,)).fetchone():
                    self.send_error(409, "Device already registered", "Этот IP уже добавлен. Измените доступ SSH в настройках карточки.")
                    return
            private = telemetry.enroll(ip, login, fingerprint, password) if enroll else None
            with sqlite3.connect(self.server.database) as db:
                db.execute("INSERT INTO devices (ip,name,image,boot,physical_port,sd_cid) VALUES (?,?,?,?,?,?)",
                           (ip, name, next(iter(IMAGES)), next(iter(BOOT)), port, cid))
                if private:
                    save_ssh(db, ip, login, fingerprint, private, self.server.credential_cipher, password)
        self.redirect()

    def redirect(self):
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--network", required=True, type=ipaddress.IPv4Network)
    parser.add_argument("--test-pi")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--origin", default="http://127.0.0.1:8084")
    parser.add_argument("--port", type=int, default=8084)
    parser.add_argument("--admin-port", type=int)
    parser.add_argument("--switch-config", default="/switch")
    parser.add_argument("--https-origin")
    parser.add_argument("--tls-dir", type=Path)
    parser.add_argument("--allowed-origin", action="append", default=[])
    parser.add_argument("--boot-host", type=ipaddress.IPv4Address)
    parser.add_argument("--management-networks", default="")
    args = parser.parse_args()
    management_networks = tuple(ipaddress.IPv4Network(value.strip())
                                for value in args.management_networks.split(",") if value.strip())
    with sqlite3.connect(args.database) as db:
        schema(db)
        db.execute("CREATE TABLE IF NOT EXISTS consoles (ip TEXT PRIMARY KEY, url TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS eeprom_credentials (ip TEXT PRIMARY KEY, secret BLOB NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS poe_registrations (ip TEXT PRIMARY KEY, port INTEGER NOT NULL, switch_target TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, name TEXT NOT NULL, image TEXT NOT NULL, boot TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS samples (ip TEXT NOT NULL, checked INTEGER NOT NULL, online INTEGER NOT NULL, PRIMARY KEY (ip, checked))")
        db.execute("CREATE TABLE IF NOT EXISTS collectors (ip TEXT PRIMARY KEY, login TEXT, fingerprint TEXT, private TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS metrics (ip TEXT, checked INTEGER, ticks INTEGER, idle INTEGER, mem INTEGER, used INTEGER, rx INTEGER, tx INTEGER, disk INTEGER, PRIMARY KEY(ip, checked))")
        if "physical_port" not in {row[1] for row in db.execute("PRAGMA table_info(devices)")}:
            db.execute("ALTER TABLE devices ADD COLUMN physical_port INTEGER CHECK (physical_port BETWEEN 1 AND 24)")
        if "sd_cid" not in {row[1] for row in db.execute("PRAGMA table_info(devices)")}:
            db.execute("ALTER TABLE devices ADD COLUMN sd_cid TEXT")
            seed = Switch(args.switch_config).directory / "install-device.json"
            if seed.is_file():
                device = json.loads(seed.read_text())
                db.execute("UPDATE devices SET sd_cid=? WHERE ip=?", (device["cid"], device["ip"]))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS devices_physical_port ON devices(physical_port)")
    Path(args.database).chmod(0o600)

    credential_file = args.tls_dir / "ssh-credentials.key" if args.tls_dir else None
    cipher = Fernet(credential_file.read_bytes().strip()) if credential_file and credential_file.is_file() else None
    switch = Switch(args.switch_config)
    static_ports = frozenset(switch.ports)
    with sqlite3.connect(args.database) as db:
        switch.load_registrations(db)
    mapping_lock = threading.Lock()
    locks = {}
    locks_guard = threading.Lock()

    def device_lock(ip):
        with locks_guard:
            return locks.setdefault(ip, threading.Lock())

    def create_server(port, origin, admin, auth_digest=None):
        handler = HTTPSRedirect if args.https_origin and not admin else Panel
        server = ThreadingHTTPServer((args.bind, port), handler)
        server.switch = switch
        server.static_ports = static_ports
        server.device_lock = device_lock
        server.mapping_lock = mapping_lock
        server.admin = admin
        server.credential_cipher = cipher if admin else None
        server.auth_digest = auth_digest
        server.admin_url = args.https_origin or "http://127.0.0.1:8085/"
        if args.https_origin and args.boot_host and not (args.tls_dir / "domain.crt").is_file():
            server.admin_url = "https://" + str(args.boot_host)
        server.ca_path = args.tls_dir / "ca.crt" if args.tls_dir else None
        server.test_pi = args.test_pi
        server.origin = origin
        server.allowed_origins = {origin, *args.allowed_origin} if admin else {origin}
        server.boot_host = str(args.boot_host) if args.boot_host else urlsplit(args.origin).hostname
        server.database = args.database
        server.network = args.network
        server.management_networks = management_networks
        return server

    if args.https_origin:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.tls_dir / "server.crt", args.tls_dir / "server.key")
        # Preserve the existing IP certificate and use the public domain certificate via SNI.
        domain_cert, domain_key = args.tls_dir / "domain.crt", args.tls_dir / "domain.key"
        if domain_cert.is_file() and domain_key.is_file():
            domain_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            domain_tls.load_cert_chain(domain_cert, domain_key)
            domain_name = urlsplit(args.https_origin).hostname
            def select_certificate(connection, name, context):
                if name == domain_name:
                    connection.context = domain_tls
            tls.set_servername_callback(select_certificate)
        digest = (args.tls_dir / "auth.sha256").read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            parser.error("Invalid HTTPS authentication digest")
        https = create_server(8443, args.https_origin, True, digest)
        https.socket = tls.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
    if args.admin_port and not args.https_origin:
        admin = create_server(args.admin_port, f"http://127.0.0.1:{args.admin_port}", True)
        threading.Thread(target=admin.serve_forever, daemon=True).start()
    threading.Thread(target=monitor, args=(args.database, cipher, device_lock), daemon=True).start()
    with create_server(args.port, args.origin, False) as server:
        server.serve_forever()
