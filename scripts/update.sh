#!/usr/bin/env bash
#
# PrivateDNS updater.
#
# The rule this script exists to enforce: never leave the service worse than it
# was found. Every step before the swap is reversible, the swap itself keeps
# the previous binaries, and a failed health check puts them back.
#
#   private-dns update            # to the latest release
#   private-dns update v0.3.0     # to a specific one
#   private-dns update --check    # report only, change nothing

set -euo pipefail

REPO="Sakawat-hossain/PrivateDNS"
PREFIX="${PREFIX:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/private-dns}"
DATA_DIR="${DATA_DIR:-/var/lib/private-dns}"
BACKUP_DIR="${BACKUP_DIR:-${DATA_DIR}/backups}"
ROLLBACK_DIR="${DATA_DIR}/rollback"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
if [[ ! -t 1 ]]; then RED=''; GREEN=''; YELLOW=''; BOLD=''; OFF=''; fi

step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$OFF" "$*"; }
fail() { printf '  %s✗%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

detect_installed() {
  INSTALLED=()
  local comp
  for comp in resolver backend portal admin; do
    [[ -x "${PREFIX}/privatedns-${comp}" ]] && INSTALLED+=("$comp")
  done
  [[ ${#INSTALLED[@]} -gt 0 ]] || fail "nothing appears to be installed under ${PREFIX}"

  RUNNING=()
  for comp in "${INSTALLED[@]}"; do
    systemctl is-active --quiet "privatedns-${comp}" 2>/dev/null && RUNNING+=("$comp")
  done
}

current_version() {
  "${PREFIX}/privatedns-resolver" -version 2>/dev/null || echo "unknown"
}

latest_version() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' | cut -d'"' -f4
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

# ---------------------------------------------------------------------------

do_check() {
  local current target
  current="$(current_version)"
  target="$(latest_version)"

  printf '  installed: %s\n  available: %s\n\n' "$current" "$target"
  if [[ "$current" == "$target" ]]; then
    ok "up to date"
  else
    printf '  Run %sprivate-dns update%s to upgrade.\n' "$BOLD" "$OFF"
  fi
}

# backup_everything runs before anything is touched.
#
# The database backup uses the resolver's own -backup, which takes a consistent
# snapshot through SQLite. Copying the file would capture the main database
# without its write-ahead log and produce something that restores to a torn
# state — silently, and only discovered when it is needed.
backup_everything() {
  step "Backing up"

  STAMP="$(date -u +%Y%m%d-%H%M%S)"
  local dest="${BACKUP_DIR}/pre-update-${STAMP}"
  install -d -m 0700 "$dest"

  if [[ -f "${CONFIG_DIR}/config.json" ]]; then
    tar -czf "${dest}/config.tar.gz" -C "$(dirname "$CONFIG_DIR")" "$(basename "$CONFIG_DIR")" 2>/dev/null
    chmod 0600 "${dest}/config.tar.gz"
    ok "configuration"
  fi

  if [[ -x "${PREFIX}/privatedns-resolver" && -f "${CONFIG_DIR}/config.json" ]]; then
    if "${PREFIX}/privatedns-resolver" -config "${CONFIG_DIR}/config.json" \
         -backup "${dest}/policy.db" >/dev/null 2>&1; then
      ok "database (verified)"
    else
      fail "the database backup failed; not proceeding with the update"
    fi
  fi

  rm -rf "$ROLLBACK_DIR"
  install -d -m 0700 "$ROLLBACK_DIR"
  local comp
  for comp in "${INSTALLED[@]}"; do
    cp -p "${PREFIX}/privatedns-${comp}" "${ROLLBACK_DIR}/privatedns-${comp}"
  done
  ok "previous binaries kept for rollback"

  BACKUP_PATH="$dest"
}

download_release() {
  step "Downloading ${TARGET_VERSION}"

  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT

  local base="https://github.com/${REPO}/releases/download/${TARGET_VERSION}"
  curl -fsSL "${base}/SHA256SUMS" -o "${WORK}/SHA256SUMS" \
    || fail "could not fetch SHA256SUMS for ${TARGET_VERSION}"

  local comp binary
  for comp in "${INSTALLED[@]}"; do
    binary="privatedns-${comp}-linux-${ARCH}"
    curl -fsSL "${base}/${binary}" -o "${WORK}/${binary}" \
      || fail "could not download ${binary}"
  done

  step "Verifying"

  # Signature first, where possible.
  #
  # A checksum proves the download matches SHA256SUMS. It says nothing about
  # whether SHA256SUMS itself is genuine — an attacker who can substitute the
  # binaries can substitute that file alongside them. The cosign signature is
  # what makes the checksums worth checking, because it binds them to this
  # project's release workflow.
  if command -v cosign >/dev/null 2>&1; then
    if curl -fsSL "${base}/SHA256SUMS.sig" -o "${WORK}/SHA256SUMS.sig" 2>/dev/null &&
       curl -fsSL "${base}/SHA256SUMS.pem" -o "${WORK}/SHA256SUMS.pem" 2>/dev/null; then
      if cosign verify-blob \
           --signature "${WORK}/SHA256SUMS.sig" \
           --certificate "${WORK}/SHA256SUMS.pem" \
           --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@" \
           --certificate-oidc-issuer https://token.actions.githubusercontent.com \
           "${WORK}/SHA256SUMS" >/dev/null 2>&1; then
        ok "signature verified"
      else
        fail "SIGNATURE VERIFICATION FAILED — nothing has been changed"
      fi
    else
      warn "this release carries no signature; falling back to checksums alone"
    fi
  else
    # Not fatal: cosign is not installed by default anywhere, and refusing to
    # update without it would push people toward downloading binaries by hand,
    # which is worse. But it is worth saying.
    warn "cosign is not installed; verifying checksums only"
    warn "  install it to verify signatures: https://docs.sigstore.dev/cosign/installation/"
  fi

  ( cd "$WORK" && grep -E "linux-${ARCH}\$|linux-${ARCH} " SHA256SUMS > wanted.txt || true
    [[ -s wanted.txt ]] || { echo "no matching checksums" >&2; exit 1; }
    sha256sum -c --ignore-missing wanted.txt >/dev/null 2>&1 ) \
    || fail "checksum verification FAILED — nothing has been changed"
  ok "checksums verified"

  # A binary that will not even report its version is not one to install.
  chmod +x "${WORK}/privatedns-resolver-linux-${ARCH}"
  "${WORK}/privatedns-resolver-linux-${ARCH}" -version >/dev/null 2>&1 \
    || fail "the downloaded binary does not run on this host"
  ok "the new binary runs here"
}

swap_binaries() {
  step "Installing"

  local comp
  for comp in "${INSTALLED[@]}"; do
    install -m 0755 "${WORK}/privatedns-${comp}-linux-${ARCH}" "${PREFIX}/.privatedns-${comp}.new"
    mv -f "${PREFIX}/.privatedns-${comp}.new" "${PREFIX}/privatedns-${comp}"
  done
  ok "${#INSTALLED[@]} binaries"
}

restart_services() {
  step "Restarting"

  local comp
  for comp in "${RUNNING[@]}"; do
    systemctl restart "privatedns-${comp}" || true
  done
  sleep 3
}

# verify_health decides whether the update stands.
#
# It checks that services are actually running and that the resolver reports
# ready — not merely that a process exists. A binary that starts, fails to open
# its database and exits two seconds later would pass a naive check.
verify_health() {
  step "Verifying health"

  local failed=()
  local comp
  for comp in "${RUNNING[@]}"; do
    if systemctl is-active --quiet "privatedns-${comp}"; then
      ok "privatedns-${comp} running"
    else
      warn "privatedns-${comp} is NOT running"
      failed+=("$comp")
    fi
  done

  if [[ " ${RUNNING[*]} " == *" resolver "* ]]; then
    local i answered=0
    for i in $(seq 1 10); do
      if curl -fsS --max-time 2 "http://127.0.0.1:8053/healthz" >/dev/null 2>&1; then
        answered=1
        break
      fi
      sleep 1
    done
    if [[ $answered -eq 1 ]]; then
      ok "the resolver is answering"
    else
      warn "the resolver is not answering on its admin endpoint"
      failed+=("resolver")
    fi
  fi

  [[ ${#failed[@]} -eq 0 ]]
}

rollback() {
  printf '\n%sRolling back.%s\n\n' "$BOLD" "$OFF"

  local comp
  for comp in "${INSTALLED[@]}"; do
    if [[ -f "${ROLLBACK_DIR}/privatedns-${comp}" ]]; then
      install -m 0755 "${ROLLBACK_DIR}/privatedns-${comp}" "${PREFIX}/.privatedns-${comp}.new"
      mv -f "${PREFIX}/.privatedns-${comp}.new" "${PREFIX}/privatedns-${comp}"
      ok "restored privatedns-${comp}"
    fi
  done

  for comp in "${RUNNING[@]}"; do
    systemctl restart "privatedns-${comp}" >/dev/null 2>&1 || true
  done
  sleep 3

  local recovered=1
  for comp in "${RUNNING[@]}"; do
    systemctl is-active --quiet "privatedns-${comp}" || recovered=0
  done

  if [[ $recovered -eq 1 ]]; then
    printf '\n  %sThe previous version is running again.%s\n' "$GREEN" "$OFF"
    printf '  The update failed and was reverted. Nothing was lost.\n\n'
    printf '  Logs from the attempt: journalctl -u privatedns-resolver -n 50\n'
    printf '  Backup taken beforehand: %s\n\n' "$BACKUP_PATH"
  else
    # The one case worth being loud about.
    printf '\n  %sROLLBACK DID NOT FULLY RECOVER.%s\n\n' "$RED" "$OFF"
    printf '  Previous binaries: %s\n' "$ROLLBACK_DIR"
    printf '  Database backup:   %s/policy.db\n' "$BACKUP_PATH"
    printf '  Config backup:     %s/config.tar.gz\n\n' "$BACKUP_PATH"
    printf '  Restore the database with: private-dns restore %s/policy.db\n\n' "$BACKUP_PATH"
  fi
  exit 1
}

main() {
  [[ $EUID -eq 0 ]] || fail "run this with sudo"

  if [[ "${1:-}" == "--check" ]]; then
    do_check
    exit 0
  fi

  detect_arch
  detect_installed

  local current
  current="$(current_version)"
  TARGET_VERSION="${1:-$(latest_version)}"
  [[ -n "$TARGET_VERSION" ]] || fail "could not determine a target version"

  # The tag becomes a path segment in the download URL. Reject anything that
  # is not one here, where the message can say so plainly.
  if [[ ! "$TARGET_VERSION" =~ ^v?[0-9A-Za-z._-]+$ ]]; then
    fail "'${TARGET_VERSION}' is not a valid release tag"
  fi

  printf '\n  %s → %s\n  components: %s\n\n' "$current" "$TARGET_VERSION" "${INSTALLED[*]}"

  if [[ "$current" == "$TARGET_VERSION" ]]; then
    ok "already on ${TARGET_VERSION}"
    exit 0
  fi

  backup_everything
  download_release
  swap_binaries
  restart_services

  if verify_health; then
    printf '\n  %sUpdated to %s.%s\n\n' "$GREEN" "$TARGET_VERSION" "$OFF"
    printf '  Backup from before the update: %s\n' "$BACKUP_PATH"
    printf '  Previous binaries, if needed:  %s\n\n' "$ROLLBACK_DIR"
  else
    rollback
  fi
}

main "$@"
