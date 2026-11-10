"""Read-only Raspberry Pi telemetry over a pinned SSH connection."""
import base64
import hashlib
import io
import shlex

import paramiko

COMMAND = """head -n 1 /proc/stat; grep -E '^Mem(Total|Available):' /proc/meminfo; cat /proc/net/dev; df -Pk /"""


class PinnedKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint

    def missing_host_key(self, client, hostname, key):
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if "SHA256:" + digest != self.fingerprint:
            raise paramiko.SSHException("Unexpected SSH host key")


def connect(ip, login, fingerprint, **credentials):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedKey(fingerprint))
    try:
        client.connect(ip, username=login, timeout=4, banner_timeout=4, auth_timeout=4,
                       look_for_keys=False, allow_agent=False, **credentials)
    except Exception:
        client.close()
        raise
    return client


def run(client, command):
    stdin, stdout, stderr = client.exec_command(command, timeout=5)
    stdin.close()
    result = stdout.read(16385)
    if len(result) > 16384 or stdout.channel.recv_exit_status():
        raise paramiko.SSHException("Telemetry command failed")
    return result.decode()


def enroll(ip, login, fingerprint, password):
    key = paramiko.RSAKey.generate(2048)
    line = f'restrict,command="{COMMAND}" {key.get_name()} {key.get_base64()} pi-fleet-metrics'
    with connect(ip, login, fingerprint, password=password) as client:
        run(client, "umask 077; mkdir -p ~/.ssh && printf '\\n%s\\n' " +
            shlex.quote(line) + " >> ~/.ssh/authorized_keys")
    with connect(ip, login, fingerprint, pkey=key) as client:
        run(client, COMMAND)
    private = io.StringIO()
    key.write_private_key(private)
    return private.getvalue()


def collect(ip, login, fingerprint, private):
    key = paramiko.RSAKey.from_private_key(io.StringIO(private))
    with connect(ip, login, fingerprint, pkey=key) as client:
        lines = run(client, COMMAND).splitlines()
    ticks = list(map(int, lines[0].split()[1:9]))
    mem = {name.rstrip(":"): int(value) for name, value, _ in
           (line.split() for line in lines[1:3])}
    rx, tx = 0, 0
    for line in lines[3:-2]:
        name, sep, counters = line.partition(":")
        if sep and name.strip() != "lo":
            values = counters.split()
            rx += int(values[0])
            tx += int(values[8])
    disk = lines[-1].split()
    return (sum(ticks), ticks[3] + ticks[4], mem["MemTotal"],
            mem["MemTotal"] - mem["MemAvailable"], rx, tx, int(disk[4].rstrip("%")))
