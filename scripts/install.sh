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
# The release to install. VERSION is the documented override, but it is
# immediately copied: /etc/os-release assigns VERSION too, and anything read
# from it must not be able to reach the download URL.
RELEASE_TAG="${VERSION:-latest}"

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

  # Read the fields in a subshell rather than sourcing into this one.
  #
  # /etc/os-release defines NAME, ID and VERSION. Sourcing it directly
  # overwrites any variable of those names already set here — and VERSION is
  # the release being installed. On Debian 12 that silently became
  # "12 (bookworm)", so the download URL was
  # releases/download/12 (bookworm)/SHA256SUMS and the install failed with a
  # message that pointed nowhere near the cause.
  local os_pretty os_family
  # shellcheck disable=SC1091
  os_pretty="$( . /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-${NAME:-unknown}}" )"
  # shellcheck disable=SC1091
  os_family="$( . /etc/os-release 2>/dev/null && printf '%s' "${ID:-}${ID_LIKE:-}" )"

  case "$os_family" in
    *debian*|*ubuntu*) ok "$os_pretty" ;;
    *)
      # Not refused: the units and paths are generic enough to work elsewhere.
      # But it is untested, and saying so is better than a surprise later.
      warn "$os_pretty is not a tested platform; Debian and Ubuntu are"
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
    # Capture, then test. `ss ... | grep -q .` reads naturally but grep exits at
    # the first line it sees, ss is left writing to a closed pipe and dies with
    # SIGPIPE, and pipefail makes the pipeline return 141 -- which `if` reads as
    # false. So a busy port was silently reported as FREE, the install carried
    # on, and the resolver then failed to bind. The check existed to catch
    # exactly the case it got wrong.
    local listeners
    listeners="$(ss -Hln "sport = :${port}" 2>/dev/null || true)"
    if [[ -n "${listeners//[[:space:]]/}" ]]; then
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

# Ask GitHub for the newest published tag.
#
# Deliberately not `curl ... | grep -m1 ... | cut`. grep -m1 exits at the first
# match, curl is left writing to a closed pipe, and dies with
# "curl: (23) Failure writing output to destination" -- which `set -o pipefail`
# then turns into a failed pipeline even though the fetch itself worked fine.
# Fetch into a variable, parse it afterwards, and there is no pipe left for
# anything to break.
latest_release_tag() {
  local json tag
  json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")" || return 1

  tag="${json#*\"tag_name\"}"
  [[ "$tag" != "$json" ]] || return 1   # key absent
  tag="${tag#*:}"
  tag="${tag#*\"}"
  tag="${tag%%\"*}"

  [[ -n "$tag" ]] || return 1
  printf '%s' "$tag"
}

resolve_version() {
  if [[ "$RELEASE_TAG" == "latest" ]]; then
    RELEASE_TAG="$(latest_release_tag)" \
      || fail "could not determine the latest release"
    [[ -n "$RELEASE_TAG" ]] || fail "could not determine the latest release"
  fi

  # A tag is a path segment in every download URL below. Anything with a space
  # or a slash in it is not a tag, and pasting it into a URL produces a curl
  # error that says nothing about where the value came from. Reject it here,
  # where the message can name the real problem.
  if [[ ! "$RELEASE_TAG" =~ ^v?[0-9A-Za-z._-]+$ ]]; then
    fail "'${RELEASE_TAG}' is not a valid release tag; set VERSION to a published tag or leave it unset"
  fi

  ok "version ${RELEASE_TAG}"
}

download_and_verify() {
  step "Downloading"

  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT

  local base="https://github.com/${REPO}/releases/download/${RELEASE_TAG}"

  curl -fsSL "${base}/SHA256SUMS" -o "${WORK}/SHA256SUMS" \
    || fail "could not fetch SHA256SUMS for ${RELEASE_TAG}"

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

  # A stale config.json from v1.0.x. The resolver reads either format -- the
  # extension picks the parser -- but the unit file names config.yaml, so a
  # leftover .json is dead weight that looks live. Say so rather than leaving
  # two configs on disk disagreeing about which one matters.
  if [[ -f "${CONFIG_DIR}/config.json" && ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    mv "${CONFIG_DIR}/config.json" "${CONFIG_DIR}/config.json.unused"
    warn "found config.json from an older install; it is not read any more"
    warn "  kept as config.json.unused -- copy anything you customised into config.yaml"
  fi

  if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    ADMIN_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    cat > "${CONFIG_DIR}/config.yaml" <<EOF
# PrivateDNS resolver configuration, written by the installer.
#
# Every key can also be set from the environment as PRIVATEDNS_<KEY>, and the
# environment wins over this file.

# The name customers point their device at. Change this before going live.
base_domain: dns.example.com

cert_file: ${CONFIG_DIR}/certs/fullchain.pem
key_file: ${CONFIG_DIR}/certs/privkey.pem

listen_dot: ":853"
listen_doh: ":443"
listen_plain: ":53"
listen_admin: "127.0.0.1:8053"

upstreams:
  - "1.1.1.1:53"
  - "1.0.0.1:53"

db_path: ${DATA_DIR}/policy.db
blocklist_dir: ${DATA_DIR}/blocklists

# Anyone holding this token can provision tenants. Keep the file mode 0640.
admin_tokens:
  - "${ADMIN_TOKEN}"

# Plain :53 identifies no tenant, so it cannot be filtered per customer.
open_plain: false

rate_limit_qps: 50
rate_limit_burst: 200
strip_ecs: true
log_level: info
EOF
    chmod 0640 "${CONFIG_DIR}/config.yaml"
    chown root:"$SERVICE_USER" "${CONFIG_DIR}/config.yaml"
    generated=1
    ok "config.yaml created"
  else
    ok "config.yaml exists, left alone"
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
      curl -fsSL "https://raw.githubusercontent.com/${REPO}/${RELEASE_TAG}/deploy/systemd/privatedns-${comp}.service" \
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
    RESOLVER_UP=1
    ok "privatedns-resolver running"
  else
    RESOLVER_UP=0
    warn "privatedns-resolver did not start"
    printf '\n'
    journalctl -u privatedns-resolver -n 15 --no-pager 2>/dev/null | sed 's/^/      /'
    printf '\n'
  fi
}

health_check() {
  step "Checking health"

  if [[ "${RESOLVER_UP:-0}" -ne 1 ]]; then
    warn "skipped -- the resolver is not running"
    return
  fi

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

  if [[ "${RESOLVER_UP:-0}" -eq 1 ]]; then
    cat <<EOF

${BOLD}Installed.${OFF}

The resolver is running, but it is not serving customers yet. Three things
remain, in this order:
EOF
  else
    cat <<EOF

${BOLD}Installed, but the resolver is not running.${OFF}

The files are all in place; something stopped the service from starting. The
log is printed above, and in full at:

    journalctl -u privatedns-resolver -n 50

Work through the steps below anyway -- a missing domain or certificate is the
usual cause -- then: systemctl restart privatedns-resolver
EOF
  fi

  cat <<EOF

${BOLD}1. Set your domain${OFF}

   Edit ${CONFIG_DIR}/config.yaml and replace ${domain_hint}
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
${BOLD}Your resolver admin token${OFF} (also in ${CONFIG_DIR}/config.yaml):

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

# Run only when executed, not when sourced. Sourcing defines the functions and
# does nothing else, which is what scripts/test-install.sh needs in order to
# exercise them against stubbed curl and ss.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
