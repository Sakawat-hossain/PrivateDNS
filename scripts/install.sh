#!/usr/bin/env bash
#
# PrivateDNS installer.
#
# Deliberately NOT designed to be piped into a shell. Download it, look at it,
# check the checksum, then run it:
#
#   curl -fsSLO https://github.com/Sakawat-hossain/PrivateDNS/releases/latest/download/install.sh
#   curl -fsSLO https://github.com/Sakawat-hossain/PrivateDNS/releases/latest/download/install.sh.sha256
#   sha256sum -c install.sh.sha256
#   sudo bash install.sh
#
# `curl ... | sudo bash` hands root to whatever the server returns, with no
# opportunity to see it and no protection if the download is tampered with. For
# a product whose entire pitch is trust, that is the wrong first impression.
#
# Safe to re-run: an existing installation is upgraded in place, and
# configuration files that already exist are never overwritten.

set -euo pipefail

REPO="Sakawat-hossain/PrivateDNS"
VERSION="${VERSION:-latest}"

PREFIX="${PREFIX:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/private-dns}"
DATA_DIR="${DATA_DIR:-/var/lib/private-dns}"
SERVICE_USER="${SERVICE_USER:-privatedns}"

# Components. The resolver is mandatory; the rest are optional but installed by
# default because a resolver with nothing to administer it is not much use.
COMPONENTS="${COMPONENTS:-resolver backend portal admin}"

# ---------------------------------------------------------------------------

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
if [[ ! -t 1 ]]; then RED=''; GREEN=''; YELLOW=''; BOLD=''; OFF=''; fi

step()  { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
ok()    { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }
warn()  { printf '  %s!%s %s\n' "$YELLOW" "$OFF" "$*"; }
fail()  { printf '  %s✗%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

require_root() {
  [[ $EUID -eq 0 ]] || fail "run this with sudo"
}

check_os() {
  step "Checking the system"

  [[ -f /etc/os-release ]] || fail "cannot identify this system (no /etc/os-release)"
  # shellcheck disable=SC1091
  . /etc/os-release

  case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) ok "${PRETTY_NAME:-$ID}" ;;
    *)
      # Not refused: the units and paths are generic enough to work elsewhere.
      # But it is untested, and saying so is better than a surprise later.
      warn "${PRETTY_NAME:-$ID} is not a tested platform; Debian and Ubuntu are"
      ;;
  esac

  command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) fail "unsupported architecture: $(uname -m); amd64 and arm64 are published" ;;
  esac
  ok "architecture ${ARCH}"

  for tool in curl sha256sum install useradd; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is required but not installed"
  done
}

# check_ports warns rather than refuses.
#
# On a host already running a resolver — systemd-resolved binds :53 on most
# Ubuntu installs — the operator needs to decide what to do about it. Refusing
# outright would be unhelpful; installing silently onto a port that is taken
# would be worse.
check_ports() {
  step "Checking ports"

  local busy=()
  local port
  for port in 53 443 853; do
    if ss -Hln "sport = :${port}" 2>/dev/null | grep -q .; then
      busy+=("$port")
    fi
  done

  if [[ ${#busy[@]} -eq 0 ]]; then
    ok "53, 443 and 853 are free"
    return
  fi

  warn "in use already: ${busy[*]}"
  for port in "${busy[@]}"; do
    case "$port" in
      53)
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
          warn "  :53 is systemd-resolved. Free it with:"
          printf '        systemctl disable --now systemd-resolved\n'
          printf '        rm -f /etc/resolv.conf && echo "nameserver 1.1.1.1" > /etc/resolv.conf\n'
        fi
        ;;
      443) warn "  :443 is usually nginx. The resolver needs it for DoH, or set listen_doh to \"\"." ;;
      853) warn "  :853 is the DoT port and must be free." ;;
    esac
  done
  printf '\n'
  read -r -p "  Continue anyway? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || fail "stopped"
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

resolve_version() {
  if [[ "$VERSION" == "latest" ]]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep -m1 '"tag_name"' | cut -d'"' -f4)"
    [[ -n "$VERSION" ]] || fail "could not determine the latest release"
  fi
  ok "version ${VERSION}"
}

download_and_verify() {
  step "Downloading"

  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT

  local base="https://github.com/${REPO}/releases/download/${VERSION}"

  curl -fsSL "${base}/SHA256SUMS" -o "${WORK}/SHA256SUMS" \
    || fail "could not fetch SHA256SUMS for ${VERSION}"

  local comp binary
  for comp in $COMPONENTS; do
    binary="privatedns-${comp}-linux-${ARCH}"
    curl -fsSL "${base}/${binary}" -o "${WORK}/${binary}" \
      || fail "could not download ${binary}"
  done
  # Verifying every binary against the published checksums. A download that
  # was corrupted or substituted stops here rather than being installed.
  step "Verifying"

  # Signature first, where possible.
  #
  # A checksum only proves the download matches SHA256SUMS. It says nothing
  # about whether SHA256SUMS is genuine — an attacker able to substitute the
  # binaries can substitute that file alongside them. The cosign signature is
  # what makes the checksums worth checking, because it binds them to this
  # project's release workflow.
  if command -v cosign >/dev/null 2>&1 &&
     curl -fsSL "${base}/SHA256SUMS.sig" -o "${WORK}/SHA256SUMS.sig" 2>/dev/null &&
     curl -fsSL "${base}/SHA256SUMS.pem" -o "${WORK}/SHA256SUMS.pem" 2>/dev/null; then
    if cosign verify-blob \
         --signature "${WORK}/SHA256SUMS.sig" \
         --certificate "${WORK}/SHA256SUMS.pem" \
         --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@" \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com \
         "${WORK}/SHA256SUMS" >/dev/null 2>&1; then
      ok "signature verified"
    else
      fail "SIGNATURE VERIFICATION FAILED — do not proceed"
    fi
  else
    warn "not verifying signatures (cosign not installed, or none published)"
  fi

  ( cd "$WORK" && grep -E "linux-${ARCH}\$|linux-${ARCH} " SHA256SUMS > wanted.txt || true
    [[ -s wanted.txt ]] || { echo "no checksums matched this architecture" >&2; exit 1; }
    sha256sum -c --ignore-missing wanted.txt >/dev/null 2>&1 ) \
    || fail "checksum verification FAILED — do not proceed"
  ok "all binaries verified"
}

create_user_and_dirs() {
  step "Creating the service account and directories"

  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    ok "user ${SERVICE_USER} exists"
  else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "created ${SERVICE_USER}"
  fi

  install -d -m 0755 "$CONFIG_DIR"
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$CONFIG_DIR/certs"
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR/blocklists"
  install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR/backups"
  ok "directories ready"
}

install_binaries() {
  step "Installing binaries"

  local comp
  for comp in $COMPONENTS; do
    # Installing to a temporary name and moving is atomic, so a running
    # service is never reading a half-written file.
    install -m 0755 "${WORK}/privatedns-${comp}-linux-${ARCH}" "${PREFIX}/.privatedns-${comp}.new"
    mv -f "${PREFIX}/.privatedns-${comp}.new" "${PREFIX}/privatedns-${comp}"
    ok "privatedns-${comp}"
  done
}

# write_configs never overwrites an existing file.
#
# Re-running the installer to upgrade must not silently replace a configuration
# someone spent time on, or reset an admin token that other systems are using.
write_configs() {
  step "Writing configuration"

  local generated=0

  if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
    ADMIN_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    cat > "${CONFIG_DIR}/config.json" <<EOF
{
  "base_domain": "dns.example.com",
  "cert_file": "${CONFIG_DIR}/certs/fullchain.pem",
  "key_file": "${CONFIG_DIR}/certs/privkey.pem",
  "listen_dot": ":853",
  "listen_doh": ":443",
  "listen_plain": ":53",
  "listen_admin": "127.0.0.1:8053",
  "upstreams": ["1.1.1.1:53", "1.0.0.1:53"],
  "db_path": "${DATA_DIR}/policy.db",
  "blocklist_dir": "${DATA_DIR}/blocklists",
  "admin_tokens": ["${ADMIN_TOKEN}"],
  "open_plain": false,
  "rate_limit_qps": 50,
  "rate_limit_burst": 200,
  "strip_ecs": true,
  "log_level": "info"
}
EOF
    # The file carries an admin token.
    chmod 0640 "${CONFIG_DIR}/config.json"
    chown root:"$SERVICE_USER" "${CONFIG_DIR}/config.json"
    generated=1
    ok "config.json created"
  else
    ok "config.json exists, left alone"
  fi

  local comp
  for comp in backend portal admin; do
    [[ "$COMPONENTS" == *"$comp"* ]] || continue
    if [[ -f "${CONFIG_DIR}/${comp}.yaml" ]]; then
      ok "${comp}.yaml exists, left alone"
      continue
    fi
    cat > "${CONFIG_DIR}/${comp}.yaml" <<EOF
# Generated by the installer. Edit base_domain before going live.
listen: 127.0.0.1:$(component_port "$comp")
policy_db: ${DATA_DIR}/policy.db
base_domain: dns.example.com
brand_name: PrivateDNS
resolver_admin: http://127.0.0.1:8053
resolver_token: "${ADMIN_TOKEN:-}"
secure_cookies: true
log_level: info
EOF
    chmod 0640 "${CONFIG_DIR}/${comp}.yaml"
    chown root:"$SERVICE_USER" "${CONFIG_DIR}/${comp}.yaml"
    ok "${comp}.yaml created"
  done

  [[ $generated -eq 1 ]] && NEW_INSTALL=1 || NEW_INSTALL=0
}

component_port() {
  case "$1" in
    backend) echo 8080 ;;
    portal)  echo 8081 ;;
    admin)   echo 8082 ;;
    *)       echo 8090 ;;
  esac
}

install_services() {
  step "Installing services"

  local comp unit
  for comp in $COMPONENTS; do
    unit="/etc/systemd/system/privatedns-${comp}.service"
    if [[ -f "${SCRIPT_DIR}/../deploy/systemd/privatedns-${comp}.service" ]]; then
      install -m 0644 "${SCRIPT_DIR}/../deploy/systemd/privatedns-${comp}.service" "$unit"
    else
      curl -fsSL "https://raw.githubusercontent.com/${REPO}/${VERSION}/deploy/systemd/privatedns-${comp}.service" \
        -o "$unit" || fail "could not fetch the ${comp} service unit"
    fi
    ok "privatedns-${comp}.service"
  done

  systemctl daemon-reload
}

fetch_blocklists() {
  step "Fetching blocklists"

  local dest="${DATA_DIR}/blocklists"
  if curl -fsSL --max-time 120 \
      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt" \
      -o "${dest}/hagezi-light.txt.tmp"; then
    local lines
    lines=$(wc -l < "${dest}/hagezi-light.txt.tmp")
    if (( lines > 1000 )); then
      mv "${dest}/hagezi-light.txt.tmp" "${dest}/hagezi-light.txt"
      chown "$SERVICE_USER":"$SERVICE_USER" "${dest}/hagezi-light.txt"
      ok "${lines} domains"
    else
      rm -f "${dest}/hagezi-light.txt.tmp"
      warn "the download looked truncated; skipped"
    fi
  else
    warn "could not fetch a blocklist; the resolver starts without one"
  fi
}

start_services() {
  step "Starting"

  # Only the resolver starts automatically. The others need a base_domain and
  # a certificate before they do anything useful, and a service that restarts
  # in a loop on a fresh install looks like a broken installer.
  systemctl enable --now privatedns-resolver >/dev/null 2>&1 || true
  sleep 2

  if systemctl is-active --quiet privatedns-resolver; then
    ok "privatedns-resolver running"
  else
    warn "privatedns-resolver did not start"
    printf '\n'
    journalctl -u privatedns-resolver -n 15 --no-pager 2>/dev/null | sed 's/^/      /'
    printf '\n'
  fi
}

health_check() {
  step "Checking health"

  local i
  for i in $(seq 1 10); do
    if curl -fsS --max-time 2 "http://127.0.0.1:8053/healthz" >/dev/null 2>&1; then
      ok "the admin endpoint is answering"
      local ready
      ready=$(curl -fsS --max-time 3 "http://127.0.0.1:8053/readyz" 2>/dev/null || echo '')
      if grep -q '"ok":true' <<<"$ready"; then
        ok "readiness reports healthy"
      else
        # Expected on a fresh install: no certificate yet.
        warn "not ready yet — usually because no certificate is installed"
      fi
      return
    fi
    sleep 1
  done
  warn "the admin endpoint did not answer; check: journalctl -u privatedns-resolver"
}

next_steps() {
  local domain_hint="dns.example.com"

  cat <<EOF

${BOLD}Installed.${OFF}

PrivateDNS is running, but it is not serving customers yet. Three things
remain, in this order:

${BOLD}1. Set your domain${OFF}

   Edit ${CONFIG_DIR}/config.json and replace ${domain_hint}
   with the name you will actually use, then do the same in the other
   .yaml files in that directory.

${BOLD}2. Point DNS at this host${OFF}

   Two records, both to this server's public address:

     A    dns          $(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || echo 'YOUR_SERVER_IP')
     A    *.dns        $(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || echo 'YOUR_SERVER_IP')

   ${YELLOW}If your DNS is on Cloudflare, both must be DNS-only (grey cloud).${OFF}
   The orange-cloud proxy carries HTTP and cannot pass port 53 or 853.

${BOLD}3. Get a wildcard certificate${OFF}

   Per-tenant hostnames need a wildcard, and a wildcard can only be issued
   over the DNS-01 challenge. Put your DNS provider token in a root-only file
   and run the issuance script:

     printf 'CF_DNS_API_TOKEN=your_token\\n' > ${CONFIG_DIR}/cloudflare.env
     chmod 600 ${CONFIG_DIR}/cloudflare.env
     ACME_EMAIL=you@example.com BASE_DOMAIN=your.domain \\
       ${PREFIX}/privatedns-issue-cert run

   Then: systemctl restart privatedns-resolver

${BOLD}Afterwards${OFF}

   systemctl enable --now privatedns-backend privatedns-portal privatedns-admin
   private-dns status

EOF

  if [[ "${NEW_INSTALL:-0}" == "1" && -n "${ADMIN_TOKEN:-}" ]]; then
    cat <<EOF
${BOLD}Your resolver admin token${OFF} (also in ${CONFIG_DIR}/config.json):

   ${ADMIN_TOKEN}

EOF
  fi

  cat <<EOF
Documentation: https://github.com/${REPO}
Management:    private-dns {status|update|backup|restore|uninstall}

EOF
}

install_cli() {
  local src
  for src in private-dns update.sh uninstall.sh backup.sh; do
    if [[ -f "${SCRIPT_DIR}/${src}" ]]; then
      install -m 0755 "${SCRIPT_DIR}/${src}" "${PREFIX}/${src%.sh}"
    fi
  done
  if [[ -f "${SCRIPT_DIR}/../deploy/scripts/issue-cert.sh" ]]; then
    install -m 0755 "${SCRIPT_DIR}/../deploy/scripts/issue-cert.sh" "${PREFIX}/privatedns-issue-cert"
  fi
  if [[ -f "${SCRIPT_DIR}/../deploy/scripts/fetch-blocklists.sh" ]]; then
    install -m 0755 "${SCRIPT_DIR}/../deploy/scripts/fetch-blocklists.sh" "${PREFIX}/privatedns-fetch-blocklists"
  fi
}

main() {
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  printf '\n%sPrivateDNS installer%s\n\n' "$BOLD" "$OFF"

  require_root
  check_os
  check_ports
  resolve_version
  download_and_verify
  create_user_and_dirs
  install_binaries
  install_cli
  write_configs
  install_services
  fetch_blocklists
  start_services
  health_check
  next_steps
}

main "$@"
