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
# The token needs TWO permissions, both scoped to the one zone:
#
#   Zone -> DNS  -> Edit    write the _acme-challenge TXT record
#   Zone -> Zone -> Read    find the zone ID before writing to it
#
# DNS:Edit alone is not enough. lego resolves the zone by name first, and that
# call fails with an authentication error that says nothing about which
# permission is missing.

set -euo pipefail

# lego is not bundled. It is a third-party binary and this installer will not
# download and run one behind your back -- but failing with
# "lego: command not found" three steps into certificate issuance is no better,
# so say exactly what to do.
if ! command -v lego >/dev/null 2>&1; then
  cat >&2 <<'MSG'
lego is not installed. It is the ACME client this script drives.

  Debian/Ubuntu:  apt-get install -y lego

  Or the upstream binary, if your distribution has no package:

    v=$(curl -fsSL https://api.github.com/repos/go-acme/lego/releases/latest \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
    curl -fsSL "https://github.com/go-acme/lego/releases/download/${v}/lego_${v}_linux_amd64.tar.gz" \
      | tar -xz -C /tmp lego
    install -m 0755 /tmp/lego /usr/local/bin/lego

Then run this script again.
MSG
  exit 1
fi

BASE_DOMAIN="${BASE_DOMAIN:-dns.example.com}"
EMAIL="${ACME_EMAIL:?set ACME_EMAIL to the address Let\'s Encrypt should contact}"
CERT_DIR="/etc/private-dns/certs"
LEGO_DIR="/var/lib/private-dns/lego"

if [[ ! -r /etc/private-dns/cloudflare.env ]]; then
  echo "missing /etc/private-dns/cloudflare.env — see the comment at the top of this script" >&2
  exit 1
fi
# Read only the token, in a subshell. Sourcing the file directly would let
# anything else in it overwrite BASE_DOMAIN, EMAIL or CERT_DIR, which are set
# above -- the same collision that broke the installer on Debian in v1.0.0.
# shellcheck disable=SC1091
# The `|| true` is load-bearing. Under `set -e` an assignment takes the exit
# status of its command substitution, and sourcing a file that holds a bare
# token runs that token as a command -- status 127. The script then died
# there, silently, because the only message went to /dev/null, and every
# check below this line was unreachable.
CF_DNS_API_TOKEN="$( . /etc/private-dns/cloudflare.env >/dev/null 2>&1 && printf '%s' "${CF_DNS_API_TOKEN:-}" )" || true
if [[ -z "$CF_DNS_API_TOKEN" ]]; then
  # The common mistake is writing the token on its own, with no variable name.
  # This file is shell, not a bare secret: sourcing it then tries to run the
  # token as a command, and CF_DNS_API_TOKEN is never set. Name that case
  # exactly rather than saying only that the variable is missing.
  if grep -qE '^[[:space:]]*[A-Za-z0-9_-]{20,}[[:space:]]*$' \
       /etc/private-dns/cloudflare.env 2>/dev/null; then
    cat >&2 <<'MSG'
/etc/private-dns/cloudflare.env holds a bare value with no variable name.

It has to read:

    CF_DNS_API_TOKEN=your_token_here

Rewrite it, replacing YOUR_TOKEN:

    printf 'CF_DNS_API_TOKEN=YOUR_TOKEN\n' > /etc/private-dns/cloudflare.env
    chmod 600 /etc/private-dns/cloudflare.env
MSG
  else
    echo "no CF_DNS_API_TOKEN in /etc/private-dns/cloudflare.env" >&2
  fi
  exit 1
fi
export CF_DNS_API_TOKEN

echo "==> Issuing for ${BASE_DOMAIN} and *.${BASE_DOMAIN}"
echo "    Writing a TXT record at _acme-challenge.${BASE_DOMAIN} and waiting for"
echo "    Let's Encrypt to see it. A minute or two is normal."


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
echo "==> Now restart the resolver: systemctl restart privatedns-resolver"
