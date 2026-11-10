"""Serve Raspberry Pi EEPROM boot files only to the enrolled test Pi."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class BootHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, client_ip, **kwargs):
        self.client_ip = client_ip
        super().__init__(*args, **kwargs)

    def send_head(self):
        if self.client_address[0] != self.client_ip or self.path not in {
            "/boot/boot.img", "/boot/boot.sig",
        }:
            self.send_error(404)
            return None
        return super().send_head()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--port", type=int, default=8083)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    handler = partial(BootHandler, client_ip=args.client, directory=args.directory)
    with ThreadingHTTPServer((args.bind, args.port), handler) as server:
        server.serve_forever()
