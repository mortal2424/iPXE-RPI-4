"""Port-scoped SNMPv3 PoE control for explicitly mapped devices."""
import ipaddress
import json
import os
import subprocess
from pathlib import Path

PORT_ADMIN = ".1.3.6.1.2.1.105.1.1.1.3"
PORT_DETECTION = ".1.3.6.1.2.1.105.1.1.1.6"


class PoeError(Exception):
    pass


class Switch:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.target = None
        self.allow_write = False
        self.ports = {}
        path = self.directory / "switch.json"
        if not path.is_file() or not (self.directory / "snmp.conf").is_file():
            return
        data = json.loads(path.read_text())
        self.allow_write = data.get("allow_write") is True
        self.target = f"udp:{ipaddress.IPv4Address(data['address'])}:161"
        indexes = set()
        for ip, port in data["ports"].items():
            ip = str(ipaddress.IPv4Address(ip))
            group, index, number = (port[key] for key in ("group", "index", "number"))
            if any(type(value) is not int or not 0 < value <= 65535 for value in (group, index, number)):
                raise ValueError("Invalid PoE port index")
            if (group, index) in indexes:
                raise ValueError("Duplicate PoE port mapping")
            indexes.add((group, index))
            self.ports[ip] = (number, f".{group}.{index}")

    def run(self, command, *args):
        env = {**os.environ, "SNMPCONFPATH": str(self.directory), "MIBS": ""}
        try:
            return subprocess.run(
                [command, "-v3", "-l", "authPriv", "-t", "1", "-r", "0",
                 "-Oqve", self.target, *args],
                check=True, capture_output=True, text=True, timeout=4, env=env,
            ).stdout.splitlines()
        except (OSError, subprocess.SubprocessError) as error:
            raise PoeError("Switch did not confirm the SNMP operation") from error

    def status(self, ip):
        number, index = self.ports[ip]
        response = self.run("snmpget", PORT_ADMIN + index, PORT_DETECTION + index)
        try:
            enabled, detection = (int(value) for value in response)
        except ValueError as error:
            raise PoeError("Unexpected PoE status") from error
        if enabled not in (1, 2):
            raise PoeError("Unknown PoE admin value")
        return number, enabled == 1, detection == 3

    def set_power(self, ip, enabled):
        if not self.allow_write:
            raise PoeError("PoE writes are disabled")
        _, index = self.ports[ip]
        self.status(ip)
        self.run("snmpset", PORT_ADMIN + index, "i", "1" if enabled else "2")
        if self.status(ip)[1] != enabled:
            raise PoeError("Switch did not confirm the new power setting")

    def restart(self, ip):
        if not self.allow_write:
            raise PoeError("PoE writes are disabled")
        self.status(ip)
        _, index = self.ports[ip]
        oid = PORT_ADMIN + index
        try:
            self.run("snmpset", oid, "i", "2")
        finally:
            # A timed-out SET may have reached the switch.
            for attempt in range(3):
                try:
                    self.run("snmpset", oid, "i", "1")
                    if self.status(ip)[1]:
                        break
                except PoeError:
                    pass
            else:
                raise PoeError("Could not confirm PoE recovery")
