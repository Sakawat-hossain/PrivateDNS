#!/usr/bin/env bash
# Issue and renew the wildcard certificate the resolver needs.
#
# A wildcard REQUIRES the DNS-01 challenge — HTTP-01 cannot issue one. That is
# why this talks to the Cloudflare API rather than serving a file over port 80.
#
# The API token is read from /etc/private-dns/cloudflare.env, which you create on
# the server. Never put the token in this script or in version control.
#
#   printf 'CF_DNS_API_TOKEN=your_token_here\n' > /etc/private-dns/cloudflare.env
#   chmod 600 /etc/private-dns/cloudflare.env
#
# The token needs exactly one permission: Zone -> DNS -> Edit, scoped to the
# zone only.

set -euo pipefail

BASE_DOMAIN="${BASE_DOMAIN:-dns.example.com}"
EMAIL="${ACME_EMAIL:?set ACME_EMAIL to the address Let\'s Encrypt should contact}"
CERT_DIR="/etc/private-dns/certs"
LEGO_DIR="/var/lib/private-dns/lego"

if [[ ! -r /etc/private-dns/cloudflare.env ]]; then
  echo "missing /etc/private-dns/cloudflare.env — see the comment at the top of this script" >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/private-dns/cloudflare.env
export CF_DNS_API_TOKEN

mkdir -p "$CERT_DIR" "$LEGO_DIR"

# Both names are needed: the bare hostname for the setup guides and diagnostics,
# and the wildcard for every per-tenant hostname.
lego \
  --accept-tos \
  --email "$EMAIL" \
  --dns cloudflare \
  --path "$LEGO_DIR" \
  --domains "$BASE_DOMAIN" \
  --domains "*.$BASE_DOMAIN" \
  "${1:-run}"

install -m 0644 "$LEGO_DIR/certificates/$BASE_DOMAIN.crt" "$CERT_DIR/fullchain.pem"
install -m 0640 -g privatedns "$LEGO_DIR/certificates/$BASE_DOMAIN.key" "$CERT_DIR/privkey.pem"

# The resolver re-reads the certificate from disk within a minute, so a renewal
# needs no restart and drops no connections.
echo "certificate installed to $CERT_DIR"
