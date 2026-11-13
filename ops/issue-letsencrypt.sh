#!/bin/sh
set -eu
credentials=/srv/pi-reinstall/acme/selectel.ini
[ -s "$credentials" ] || { echo "Fill $credentials first" >&2; exit 1; }
exec /opt/pi-fleet-acme/bin/certbot certonly \
  --authenticator dns-selectel-api-v2 \
  --dns-selectel-api-v2-credentials "$credentials" \
  --dns-selectel-api-v2-propagation-seconds 180 \
  --non-interactive --agree-tos --register-unsafely-without-email \
  --cert-name pi.homevlad.ru -d pi.homevlad.ru \
  --deploy-hook /opt/pi-reinstall/ops/deploy-letsencrypt.sh "$@"
