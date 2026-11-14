#!/bin/sh
set -eu
cd /opt/pi-reinstall
domain=$(sed -n 's/^FLEET_DOMAIN=//p' .env | tail -n 1)
case "$domain" in
    *[!A-Za-z0-9.-]*|.*|*..*|*.) echo 'Set FLEET_DOMAIN in .env to an unquoted DNS name' >&2; exit 1 ;;
    *.*) ;;
    *) echo 'Set FLEET_DOMAIN in .env to an unquoted DNS name' >&2; exit 1 ;;
esac
credentials=/srv/pi-reinstall/acme/selectel.ini
[ -s "$credentials" ] || { echo "Fill $credentials first" >&2; exit 1; }
exec /opt/pi-fleet-acme/bin/certbot certonly \
  --authenticator dns-selectel-api-v2 \
  --dns-selectel-api-v2-credentials "$credentials" \
  --dns-selectel-api-v2-propagation-seconds 180 \
  --non-interactive --agree-tos --register-unsafely-without-email \
  --cert-name "$domain" -d "$domain" \
  --deploy-hook /opt/pi-reinstall/ops/deploy-letsencrypt.sh "$@"
