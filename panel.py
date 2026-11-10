"""Local management panel for Pi provisioning."""
import argparse
import ipaddress
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

IMAGES = {"raspios-lite-arm64": "Raspberry Pi OS Lite · 64-bit"}
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


class Panel(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        with sqlite3.connect(self.server.database) as db:
            devices = db.execute("SELECT ip, name, image, boot FROM devices ORDER BY name, ip").fetchall()
        with ThreadPoolExecutor(max_workers=8) as pool:
            states = list(pool.map(reachable, (device[0] for device in devices)))
        rows = []
        for (ip, name, image, boot), online in zip(devices, states):
            rows.append(f"""
            <article><div class="top"><h2>{escape(name)}</h2>
            <span class="badge {'up' if online else ''}">{'SSH доступен' if online else 'SSH недоступен'}</span></div>
            <p class="mono">{ip}</p>
            <form method="post" action="/preferences">
              <input type="hidden" name="ip" value="{ip}">
              <label>Образ ОС<select name="image">{options(IMAGES, image)}</select></label>
              <label>Порядок загрузки<select name="boot">{options(BOOT, boot)}</select></label>
              <button>Сохранить параметры</button>
            </form></article>""")
        html = f"""<!doctype html>
        <html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Pi Fleet · Панель управления</title><style>
        *{{box-sizing:border-box}}body{{margin:0;background:#0d151a;color:#e6edf0;font:16px system-ui}}
        main{{max-width:1000px;margin:auto;padding:36px 20px}}header{{margin-bottom:24px}}
        h1{{font-size:clamp(36px,8vw,64px);margin:6px 0}}h2{{margin:0;font-size:22px}}
        small{{color:#83e3c5;font-weight:bold;letter-spacing:.12em}}p{{color:#a8bac4}}
        .grid{{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))}}
        article,aside{{background:#152228;border:1px solid #30424a;border-radius:14px;padding:20px}}
        aside{{margin-top:20px}}.top{{display:flex;justify-content:space-between;gap:8px;align-items:center}}
        .badge{{background:#3c3130;color:#ffccc1;border-radius:20px;padding:4px 9px;font-size:13px}}
        .up{{background:#1d3c35;color:#a6f0d6}}.mono{{font-family:monospace}}
        label{{display:block;margin:12px 0}}input,select,button{{font:inherit;border-radius:8px;padding:9px}}
        input,select{{display:block;width:100%;margin-top:6px;background:#10191e;color:#e6edf0;border:1px solid #526771}}
        button{{background:#83e3c5;color:#102921;border:0;font-weight:650;cursor:pointer}}
        a{{color:#83e3c5}}footer{{margin-top:24px;color:#a8bac4}}
        </style><main><header><small>RASPBERRY PI / ЛОКАЛЬНАЯ СЕТЬ</small>
        <h1>Pi Fleet</h1><p>{sum(states)} из {len(devices)} устройств отвечают на SSH.
        <a href="/">Обновить состояние</a></p></header>
        <div class="grid">{''.join(rows) or '<p>Устройства ещё не добавлены.</p>'}</div>
        <aside><h2>Добавить Raspberry Pi</h2><form method="post" action="/devices">
        <label>Имя<input name="name" required maxlength="60" placeholder="Например, pi-lab-02"></label>
        <label>IPv4<input name="ip" required placeholder="192.168.10.250"></label>
        <button>Добавить устройство</button></form></aside>
        <footer>Состояние проверяется по порту 22. Выбор образа и порядка загрузки сохраняется в панели.
        Применение EEPROM, запуск установки и сбор метрик пока не подключены.</footer></main></html>"""
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        host = self.headers.get("Host", "")
        if f"http://{host}" != self.server.origin or self.headers.get("Origin") != self.server.origin:
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError
            data = parse_qs(self.rfile.read(length).decode(), max_num_fields=8)
            ip = ipaddress.IPv4Address(data["ip"][0])
            if ip not in self.server.network or ip in (self.server.network.network_address, self.server.network.broadcast_address):
                raise ValueError
            with sqlite3.connect(self.server.database) as db:
                if self.path == "/devices":
                    name = data["name"][0].strip()
                    if not 0 < len(name) <= 60:
                        raise ValueError
                    db.execute("INSERT INTO devices VALUES (?, ?, ?, ?)", (str(ip), name, next(iter(IMAGES)), next(iter(BOOT))))
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
        except (KeyError, ValueError):
            self.send_error(400, "Invalid device or preferences")
            return
        except sqlite3.IntegrityError:
            self.send_error(409, "Device already registered")
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--network", required=True, type=ipaddress.IPv4Network)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--origin", default="http://127.0.0.1:8084")
    parser.add_argument("--port", type=int, default=8084)
    args = parser.parse_args()
    with sqlite3.connect(args.database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, name TEXT NOT NULL, image TEXT NOT NULL, boot TEXT NOT NULL)")
    with ThreadingHTTPServer((args.bind, args.port), Panel) as server:
        server.origin = args.origin
        server.database = args.database
        server.network = args.network
        server.serve_forever()
