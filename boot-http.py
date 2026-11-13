"""Serve Raspberry Pi EEPROM boot files only to the Pi selected for installation."""
import argparse
import re
from pathlib import Path
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class BootHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, client_ip, jobs, **kwargs):
        self.client_ip = client_ip
        self.jobs = jobs
        super().__init__(*args, **kwargs)

    def is_target(self):
        target = Path(self.directory) / "boot/target.ip"
        try:
            expected = target.read_text().strip()
        except FileNotFoundError:
            expected = self.client_ip
        return self.client_address[0] == expected

    def send_head(self):
        if not self.is_target() or self.path not in {
            "/boot/boot.img", "/boot/boot.sig", "/images/raspios-lite-arm64.img.xz",
            "/images/reinstall.img.xz",
        }:
            self.send_error(404)
            return None
        return super().send_head()


    def do_POST(self):
        if not self.is_target() or self.path not in {"/claim", "/result"} or self.jobs is None:
            self.send_error(404)
            return
        if self.path == "/result":
            self.save_result()
            return
        if self.headers.get("Content-Length") != "70":
            self.send_error(400)
            return
        match = re.fullmatch(rb"token=([a-f0-9]{64})", self.rfile.read(70))
        if not match:
            self.send_error(400)
            return
        token = match[1]
        pending = self.jobs / (token.decode() + ".pending")
        try:
            pending.rename(pending.with_suffix(".claimed"))
        except FileNotFoundError:
            self.send_error(409)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(token)))
        self.end_headers()
        self.wfile.write(token)


    def save_result(self):
        size = self.headers.get("Content-Length")
        if size not in {"83", "85"}:
            self.send_error(400)
            return
        match = re.fullmatch(rb"token=([a-f0-9]{64})&state=(failed|complete)", self.rfile.read(int(size)))
        if not match:
            self.send_error(400)
            return
        claimed = self.jobs / (match[1].decode() + ".claimed")
        if not claimed.is_file():
            self.send_error(409)
            return
        result = claimed.with_suffix(".result")
        temporary = claimed.with_suffix(".result.tmp")
        temporary.write_bytes(match[2])
        temporary.replace(result)
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--port", type=int, default=8083)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--jobs", type=Path)
    args = parser.parse_args()
    handler = partial(BootHandler, client_ip=args.client, jobs=args.jobs, directory=args.directory)
    with ThreadingHTTPServer((args.bind, args.port), handler) as server:
        server.serve_forever()
