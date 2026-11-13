#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=90 install -y python3-venv
python3 -m venv /opt/pi-fleet-acme
/opt/pi-fleet-acme/bin/pip install 'certbot==5.9.0' 'certbot-dns-selectel-api-v2==0.3.0' 'zope.interface==8.7'
/opt/pi-fleet-acme/bin/python /opt/pi-reinstall/ops/patch-selectel-plugin.py
/opt/pi-fleet-acme/bin/certbot plugins
install -d -m 0700 /srv/pi-reinstall/acme
if [ ! -e /srv/pi-reinstall/acme/selectel.ini ]; then
    install -m 0600 /opt/pi-reinstall/ops/selectel.ini.example /srv/pi-reinstall/acme/selectel.ini
fi
chmod 0700 /opt/pi-reinstall/ops/deploy-letsencrypt.sh /opt/pi-reinstall/ops/issue-letsencrypt.sh
install -m 0644 /opt/pi-reinstall/ops/pi-fleet-acme-renew.service /opt/pi-reinstall/ops/pi-fleet-acme-renew.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pi-fleet-acme-renew.timer
