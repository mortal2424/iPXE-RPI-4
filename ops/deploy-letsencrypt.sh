#!/bin/sh
set -eu
certificate_dir=${RENEWED_LINEAGE:?Certbot must set RENEWED_LINEAGE}
cd /opt/pi-reinstall
domain=$(sed -n 's/^FLEET_DOMAIN=//p' .env | tail -n 1)
[ -n "$domain" ] || { echo 'Set FLEET_DOMAIN in .env' >&2; exit 1; }
[ "${certificate_dir##*/}" = "$domain" ] || exit 0
tls_dir=$(sed -n 's/^FLEET_TLS_DIR=//p' .env | tail -n 1)
tls_dir=${tls_dir:-/srv/pi-reinstall/tls}
openssl x509 -in "$certificate_dir/fullchain.pem" -noout -checkhost "$domain"
python3 - "$certificate_dir" <<'PY'
import ssl,sys
from pathlib import Path
path=Path(sys.argv[1]);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(path/'fullchain.pem',path/'privkey.pem')
PY
install -m 0640 -o root -g 10001 "$certificate_dir/fullchain.pem" "$tls_dir/.domain.crt.next"
install -m 0640 -o root -g 10001 "$certificate_dir/privkey.pem" "$tls_dir/.domain.key.next"
mv "$tls_dir/.domain.key.next" "$tls_dir/domain.key"
mv "$tls_dir/.domain.crt.next" "$tls_dir/domain.crt"
docker compose restart panel 2>&1
