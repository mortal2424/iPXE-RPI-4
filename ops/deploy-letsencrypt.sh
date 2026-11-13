#!/bin/sh
set -eu
certificate_dir=${RENEWED_LINEAGE:?Certbot must set RENEWED_LINEAGE}
tls_dir=/srv/pi-reinstall/tls
openssl x509 -in "$certificate_dir/fullchain.pem" -noout -checkhost pi.homevlad.ru
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
cd /opt/pi-reinstall
docker compose restart panel 2>&1
