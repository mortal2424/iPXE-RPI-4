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
import telemetry
from poe import PoeError, Switch

from reinstall import ACTIVE, IMAGES, STATES, cloud_config, schema, valid_account
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


def monitor(database):
    while True:
        try:
            sample_devices(database)
        except (sqlite3.Error, OSError) as error:
            print(f"Monitoring: {error}", flush=True)
        time.sleep(30)


def installation_status(database):
    with sqlite3.connect(database) as db:
        row = db.execute("SELECT status FROM reinstall WHERE id=1").fetchone()
    if row:
        return STATES[row[0]]
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


def install_busy(database):
    with sqlite3.connect(database) as db:
        row = db.execute("SELECT status FROM reinstall WHERE id=1").fetchone()
    if row:
        return row[0] in ACTIVE
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
        return '<small>Управление PoE ожидает проверки порта.</small>'
    try:
        port, enabled, delivering = server.switch.status(ip)
    except PoeError:
        return '<div class="job power"><b>PoE</b><span>Коммутатор не ответил</span></div>'
    label = "Питание подаётся" if delivering else "Включено, без нагрузки" if enabled else "Выключено"
    controls = f"""
        <p><a class="button secondary" href="{server.admin_url}">
        Питание и настройки ОС</a></p>
        <small>Управление открывается по HTTPS.</small>"""
    if server.admin:
        blocked = ip == server.test_pi and install_busy(server.database)
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
    return f'<div class="power"><div class="job"><b>PoE · порт {port}</b><span>{label}</span></div>{controls}</div>'


def render_card(device, samples, metrics, installer, power, admin, ready_images):
    ip, name, image, boot, physical_port, cid = device
    last = samples[0] if samples else None
    online = last and last[1]
    state = "SSH доступен" if online else "SSH недоступен" if last else "Ожидает проверки"
    checked = datetime.fromtimestamp(last[0]).astimezone().strftime("%H:%M:%S %Z") if last else "—"
    bars = "".join(
        f'<span class="{"good" if status else "bad"}" title="{datetime.fromtimestamp(at).astimezone():%d.%m %H:%M %Z} · {"доступен" if status else "недоступен"}"></span>'
        for at, status in reversed(samples)
    )
    status = f'<div class="job"><b>Переустановка</b><span>{installer}</span></div>' if installer else ""
    available = {key: label for key, label in IMAGES.items() if key in ready_images}
    install = f"""
      <details><summary>Настройки новой ОС</summary>
        <form method="post" action="/reinstall">
          <label>Новая ОС<select name="image" required>{options(available, image)}</select></label>
          <input type="hidden" name="ip" value="{ip}">
          <label>Имя хоста<input name="hostname" required maxlength="63"></label>
          <label>Логин<input name="login" required maxlength="32"></label>
          <label>Пароль<input type="password" name="password" required minlength="8" maxlength="128" autocomplete="new-password"></label>
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
          <button>Сохранить карточку</button>
        </form>
      </details>""" if admin else ""
    return f"""
      <article data-device="{ip}"><div class="card-head"><div class="device-icon" aria-hidden="true">Pi</div>
      <div class="identity"><h3>{escape(name)}</h3><code>{ip}{f" · порт {physical_port}" if physical_port is not None else ""}</code></div>
      <span class="badge {'up' if online else 'down' if last else ''}">{state}</span></div>
      <div class="health"><div class="line"><b>История SSH</b><span>{checked}</span></div>
      <div class="bars" aria-label="Последние проверки SSH">{bars or '<small>Пока нет данных</small>'}</div></div>
      {render_metrics(metrics)}
      {status}
      {power}
      <form method="post" action="/preferences">
        <input type="hidden" name="ip" value="{ip}">
        <div class="fields"><label>Образ ОС<select name="image">{options(IMAGES, image)}</select></label>
        <label>Желаемая загрузка<select name="boot">{options(BOOT, boot)}</select></label></div>
        <button class="secondary">Сохранить</button>
      </form>{edit}{install}</article>"""


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
        up = sum(bool(history and history[0][1]) for history in samples.values())
        down = sum(bool(history and not history[0][1]) for history in samples.values())
        installer = installation_status(self.server.database)
        rows = "".join(
            render_card(device, samples[device[0]], metrics[device[0]], installer if device[0] == self.server.test_pi else None, render_power(self.server, device[0], device[4]), self.server.admin, self.ready_images(device[0]) if device[5] and device[4] is not None else set())
            for device in devices
        )
        enroll_fields = """
        <label>SSH-логин<input name="login" autocomplete="username" placeholder="mortal"></label>
        <label>Пароль SSH<input type="password" name="password" autocomplete="current-password"></label>
        <label class="wide">Отпечаток ключа Pi<input name="fingerprint" placeholder="SHA256:…"></label>
        """ if self.server.admin else ""
        action = "/devices"
        label = "Добавить"
        hint = "" if self.server.admin else "<p>Для подключения метрик откройте защищённую панель по HTTPS.</p>"
        html = f"""<!doctype html>
        <html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Pi Fleet · Устройства</title><style>
        *{{box-sizing:border-box}}body{{margin:0;background:#f3f6f8;color:#182935;font:15px system-ui}}
        nav{{background:#fff;border-bottom:1px solid #dbe5ea}}nav div{{max-width:1100px;margin:auto;padding:16px 24px;display:flex;justify-content:space-between}}
        nav strong{{font-size:19px}}nav span,small,p,.line span,code{{color:#536973}}
        main{{max-width:1100px;margin:auto;padding:30px 24px}}h1{{font-size:clamp(32px,5vw,48px);margin:4px 0}}h2,h3,p{{margin:0}}h2{{font-size:22px}}h3{{font-size:18px;overflow-wrap:anywhere}}
        header small{{color:#08785c;letter-spacing:.12em;font-weight:700}}header p{{margin-top:8px}}
        .stats,.grid,.fields{{display:grid;gap:14px}}.stats{{grid-template-columns:repeat(3,1fr);margin:24px 0 30px}}.grid,.fields{{grid-template-columns:repeat(2,minmax(0,1fr))}}
        .stats div,article,aside{{background:#fff;border:1px solid #dbe5ea;border-radius:14px;padding:18px}}.stats strong{{display:block;font-size:30px}}.stats small{{font-size:13px}}
        .section,.line,.card-head,.job{{display:flex;justify-content:space-between;gap:10px;align-items:center}}.section{{margin-bottom:12px}}.card-head{{justify-content:flex-start}}
        .identity{{flex:1;min-width:0}}.device-icon{{display:grid;place-items:center;width:42px;height:42px;background:#e5f5ef;color:#08624e;border-radius:12px;font-weight:800}}
        .badge{{background:#edf1f4;border-radius:99px;padding:5px 9px;font-size:12px;white-space:nowrap}}
        .up{{background:#dcf5eb;color:#12664f}}.down{{background:#fce9e5;color:#9f3828}}
        .health,.job{{background:#f5f8fa;border-radius:9px;padding:10px 12px;margin-top:12px;font-size:13px}}.job span{{text-align:right}}.confirm input{{display:inline;width:auto;margin:0 5px 0 0}}
        .metrics{{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-top:12px}}.metrics div{{background:#f5f8fa;border-radius:8px;padding:8px}}.metrics b{{display:block;font-size:13px}}
        .bars{{display:flex;gap:3px;margin-top:7px;min-height:13px}}.bars span{{height:12px;flex:1;max-width:22px;border-radius:3px}}.good{{background:#42a886}}.bad{{background:#da7567}}
        label{{display:block;margin:12px 0;font-weight:600;font-size:13px}}input,select,button{{font:inherit;border-radius:8px;padding:9px}}
        input,select{{display:block;width:100%;margin-top:6px;background:#fbfcfd;color:#182935;border:1px solid #b9cbd3}}
        button,.button{{background:#08785c;color:#fff;border:1px solid transparent;font-weight:650;cursor:pointer;padding:8px 12px;border-radius:8px;text-decoration:none}}.secondary{{background:#fff;border-color:#b9cbd3;color:#08624e}}
        aside{{margin-top:20px}}aside form{{display:grid;grid-template-columns:1fr 1fr auto;align-items:end;gap:12px}}aside form button{{margin-bottom:12px}}.wide{{grid-column:1/-1}}
        footer{{margin-top:20px;color:#536973;font-size:13px}}
        @media(max-width:680px){{.grid,aside form{{grid-template-columns:1fr}}aside form button{{justify-self:start}}main{{padding:20px 14px}}.stats div{{padding:10px}}.badge{{white-space:normal}}}}
        </style><nav><div><strong>Pi Fleet</strong><span>Локальная сеть</span></div></nav>
        <main><header><small>УПРАВЛЕНИЕ RASPBERRY PI</small>
        <h1>Устройства</h1><p>Состояние, сетевой запуск и параметры переустановки.</p></header>
        <div class="stats"><div><small>Всего Pi</small><strong>{len(devices)}</strong></div>
        <div><small>SSH доступен</small><strong>{up}</strong></div><div><small>SSH недоступен</small><strong>{down}</strong></div></div>
        <div class="section"><h2>Парк устройств</h2><a class="button secondary" href="/">Обновить экран</a></div>
        <div class="grid">{rows or '<p>Устройства ещё не добавлены.</p>'}</div>
        <aside><h2>Добавить Raspberry Pi</h2>{hint}<form method="post" action="{action}">
        <label>Имя<input name="name" required maxlength="60" placeholder="pi-lab-02"></label>
        <label>IPv4<input name="ip" required placeholder="192.168.10.250"></label>
        <label>Порт коммутатора (необязательно)<input name="port" type="number" min="1" max="24" step="1" placeholder="19"></label>
        {('<label>CID SD-карты (необязательно)<input name="cid" pattern="[a-fA-F0-9]{32}" maxlength="32"></label><small>На Pi: cat /sys/block/mmcblk0/device/cid</small>') if self.server.admin else ""}
        <button>{label}</button>
        {('<button formaction="/enroll" formnovalidate>Подключить метрики</button><details class="wide"><summary>Данные SSH для метрик</summary>' + enroll_fields + '</details>') if self.server.admin else ""}
        </form></aside>
        <footer>Проверка SSH каждые 30 секунд. Состояние обновляется автоматически. Параметры загрузки и образа сохраняются как настройки.
        Переустановка доступна для зарегистрированной SD-карты.</footer></main>
        <script>
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
              for (const part of [".badge", ".health", ".metrics", ".job"]) {{
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

    def ready_images(self, ip):
        if ip != self.server.test_pi:
            return set()
        directory = self.server.switch.directory
        return {image for image in IMAGES if (directory / (image + ".ready")).is_file()}

    def do_POST(self):
        host = self.headers.get("Host", "")
        if host != urlsplit(self.server.origin).netloc or self.headers.get("Origin") != self.server.origin:
            self.send_error(403)
            return
        if not self.authorized():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError
            data = parse_qs(self.rfile.read(length).decode(), max_num_fields=8)
            ip = ipaddress.IPv4Address(data["ip"][0])
            if ip not in self.server.network or ip in (self.server.network.network_address, self.server.network.broadcast_address):
                raise ValueError
            if self.path in ("/devices", "/enroll", "/devices/edit"):
                port_text = data.get("port", [""])[0]
                port = int(port_text) if port_text else None
                cid = data.get("cid", [""])[0].strip().lower() or None
                if (port is not None and not 1 <= port <= 24
                        or cid is not None and (not self.server.admin or not re.fullmatch(r"[0-9a-f]{32}", cid))):
                    raise ValueError
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
                if not 0 < len(name) <= 60:
                    raise ValueError
                with self.server.power_lock, sqlite3.connect(self.server.database) as db:
                    if str(ip) == self.server.test_pi and install_busy(self.server.database):
                        self.send_error(409, "An installation is already active")
                        return
                    if not db.execute("UPDATE devices SET name=?, physical_port=?, sd_cid=? WHERE ip=?",
                                      (name, port, cid, str(ip))).rowcount:
                        self.send_error(404)
                        return
                self.redirect()
                return
            if self.path == "/power":
                if not self.server.admin or str(ip) not in self.server.switch.ports:
                    self.send_error(404)
                    return
                with sqlite3.connect(self.server.database) as db:
                    port = db.execute("SELECT physical_port FROM devices WHERE ip=?", (str(ip),)).fetchone()
                if not port or port[0] != self.server.switch.ports[str(ip)][0]:
                    self.send_error(409, "Device port does not match the verified PoE mapping")
                    return
                requested = data["state"][0]
                if data["confirm"][0] != "yes" or requested not in ("on", "off", "restart"):
                    raise ValueError
                with self.server.power_lock:
                    if str(ip) == self.server.test_pi and install_busy(self.server.database):
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
                    if image not in self.ready_images(str(ip)) or data["confirm"][0] != "yes":
                        raise ValueError
                    with self.server.power_lock:
                        if install_busy(self.server.database):
                            self.send_error(409, "An installation is already active")
                            return
                        with sqlite3.connect(self.server.database) as db:
                            device = db.execute("SELECT physical_port, sd_cid FROM devices WHERE ip=?", (str(ip),)).fetchone()
                            mapping = self.server.switch.ports.get(str(ip))
                            if not device or not device[1] or not self.server.switch.allow_write or not mapping or device[0] != mapping[0]:
                                self.send_error(409, "Register the SD card and verify the PoE port first")
                                return
                            db.execute("INSERT OR REPLACE INTO reinstall VALUES (1, ?, ?, ?, ?, ?, 'queued')",
                                       (str(ip), image, hostname, login, hashed))
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
            if self.path == "/enroll":
                if not self.server.admin:
                    self.send_error(404)
                    return
                name, login, fingerprint, password = (data[key][0] for key in ("name", "login", "fingerprint", "password"))
                name = name.strip()
                if (not 0 < len(name) <= 60 or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,31}", login)
                        or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) or len(password) > 256):
                    raise ValueError
                private = telemetry.enroll(str(ip), login, fingerprint, password)
                with sqlite3.connect(self.server.database) as db:
                    db.execute("INSERT INTO devices (ip, name, image, boot, physical_port, sd_cid) VALUES (?, ?, ?, ?, ?, ?) "
                               "ON CONFLICT(ip) DO NOTHING",
                               (str(ip), name, next(iter(IMAGES)), next(iter(BOOT)), port, cid))
                    db.execute("INSERT OR REPLACE INTO collectors VALUES (?, ?, ?, ?)", (str(ip), login, fingerprint, private))
                    db.execute("DELETE FROM metrics WHERE ip = ?", (str(ip),))
                self.redirect()
                return
            with sqlite3.connect(self.server.database) as db:
                if self.path == "/devices":
                    name = data["name"][0].strip()
                    if not 0 < len(name) <= 60:
                        raise ValueError
                    db.execute("INSERT INTO devices (ip, name, image, boot, physical_port, sd_cid) VALUES (?, ?, ?, ?, ?, ?)",
                               (str(ip), name, next(iter(IMAGES)), next(iter(BOOT)), port, cid))
                elif self.path == "/preferences":
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
            self.send_error(422, "SSH enrollment failed. Check login, password and host fingerprint.")
            return
        except (KeyError, ValueError):
            self.send_error(400, "Invalid device or preferences")
            return
        except sqlite3.IntegrityError:
            self.send_error(409, "Device already registered")
            return
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
    args = parser.parse_args()
    with sqlite3.connect(args.database) as db:
        schema(db)
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

    switch = Switch(args.switch_config)
    power_lock = threading.Lock()

    def create_server(port, origin, admin, auth_digest=None):
        server = ThreadingHTTPServer((args.bind, port), Panel)
        server.switch = switch
        server.power_lock = power_lock
        server.admin = admin
        server.auth_digest = auth_digest
        server.admin_url = args.https_origin or "http://127.0.0.1:8085/"
        server.ca_path = args.tls_dir / "ca.crt" if args.tls_dir else None
        server.test_pi = args.test_pi
        server.origin = origin
        server.database = args.database
        server.network = args.network
        return server

    if args.https_origin:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.tls_dir / "server.crt", args.tls_dir / "server.key")
        digest = (args.tls_dir / "auth.sha256").read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            parser.error("Invalid HTTPS authentication digest")
        https = create_server(8443, args.https_origin, True, digest)
        https.socket = tls.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
    if args.admin_port and not args.https_origin:
        admin = create_server(args.admin_port, f"http://127.0.0.1:{args.admin_port}", True)
        threading.Thread(target=admin.serve_forever, daemon=True).start()
    threading.Thread(target=monitor, args=(args.database,), daemon=True).start()
    with create_server(args.port, args.origin, False) as server:
        server.serve_forever()
