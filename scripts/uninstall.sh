#!/usr/bin/env bash
#
# PrivateDNS uninstaller.
#
# Customer data is never removed without being asked for explicitly, twice.
# An uninstaller that quietly deletes the database is one bad command away from
# destroying a business, and "I meant to remove the binaries" is a common
# enough intention that it should be the default.

set -euo pipefail

PREFIX="${PREFIX:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/private-dns}"
DATA_DIR="${DATA_DIR:-/var/lib/private-dns}"
SERVICE_USER="${SERVICE_USER:-privatedns}"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
if [[ ! -t 1 ]]; then RED=''; GREEN=''; YELLOW=''; BOLD=''; OFF=''; fi

COMPONENTS="resolver backend portal admin"

[[ $EUID -eq 0 ]] || { printf '%s✗%s run this with sudo\n' "$RED" "$OFF" >&2; exit 1; }

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

# ---------------------------------------------------------------------------
# Say exactly what will happen, before anything happens
# ---------------------------------------------------------------------------

tenant_count() {
  if [[ -x "${PREFIX}/privatedns-resolver" && -f "${DATA_DIR}/policy.db" ]]; then
    "${PREFIX}/privatedns-resolver" -verify-backup "${DATA_DIR}/policy.db" 2>/dev/null \
      | grep -o '[0-9]* tenants' || echo "unknown tenants"
  else
    echo "unknown tenants"
  fi
}

printf '\n%sUninstalling PrivateDNS%s\n\n' "$BOLD" "$OFF"

printf '  %sWill be removed:%s\n' "$BOLD" "$OFF"
for comp in $COMPONENTS; do
  [[ -x "${PREFIX}/privatedns-${comp}" ]] && printf '    %s/privatedns-%s\n' "$PREFIX" "$comp"
done
printf '    systemd units for the above\n'
printf '    %s/private-dns, update, backup, uninstall\n' "$PREFIX"
printf '\n'

if [[ $PURGE -eq 1 ]]; then
  printf '  %sWILL ALSO BE DELETED (--purge):%s\n' "$RED" "$OFF"
  printf '    %s — configuration and certificates\n' "$CONFIG_DIR"
  printf '    %s — %sthe customer database (%s)%s\n' "$DATA_DIR" "$RED" "$(tenant_count)" "$OFF"
  printf '    %s — every backup on this host\n' "${DATA_DIR}/backups"
  printf '    the %s system account\n' "$SERVICE_USER"
  printf '\n'
  printf '  %sThis cannot be undone.%s\n\n' "$RED" "$OFF"
else
  printf '  %sWill be KEPT:%s\n' "$GREEN" "$OFF"
  printf '    %s — configuration and certificates\n' "$CONFIG_DIR"
  printf '    %s — the customer database (%s)\n' "$DATA_DIR" "$(tenant_count)"
  printf '    %s — backups\n' "${DATA_DIR}/backups"
  printf '    the %s system account\n' "$SERVICE_USER"
  printf '\n'
  printf '  Reinstalling later will pick these up and carry on.\n'
  printf '  To delete them too, run: %sprivate-dns uninstall --purge%s\n\n' "$BOLD" "$OFF"
fi

read -r -p "  Type the word uninstall to continue: " reply
[[ "$reply" == "uninstall" ]] || { printf '  stopped\n\n'; exit 1; }

# A second, harder confirmation only when data is at stake. The first prompt
# guards a reversible action; this one does not.
if [[ $PURGE -eq 1 ]]; then
  printf '\n  %sLast chance.%s Every customer record and all backups will be deleted.\n' "$RED" "$OFF"
  read -r -p "  Type DELETE ALL DATA to confirm: " confirm
  [[ "$confirm" == "DELETE ALL DATA" ]] || { printf '  stopped — nothing was removed\n\n'; exit 1; }
fi

# ---------------------------------------------------------------------------

printf '\n'

printf '  Stopping services...\n'
for comp in $COMPONENTS; do
  systemctl disable --now "privatedns-${comp}" >/dev/null 2>&1 || true
done

printf '  Removing units...\n'
for comp in $COMPONENTS; do
  rm -f "/etc/systemd/system/privatedns-${comp}.service"
done
systemctl daemon-reload
systemctl reset-failed >/dev/null 2>&1 || true

printf '  Removing binaries...\n'
for comp in $COMPONENTS; do
  rm -f "${PREFIX}/privatedns-${comp}"
done
rm -f "${PREFIX}/private-dns" "${PREFIX}/update" "${PREFIX}/uninstall" \
      "${PREFIX}/backup" "${PREFIX}/privatedns-issue-cert" \
      "${PREFIX}/privatedns-fetch-blocklists"

if [[ $PURGE -eq 1 ]]; then
  printf '  Deleting data...\n'

  # The most dangerous line in this repository, so it is guarded explicitly.
  # An empty or root path here would be catastrophic, and these variables are
  # overridable from the environment.
  for dir in "$CONFIG_DIR" "$DATA_DIR"; do
    case "$dir" in
      ""|"/"|"/*"|"/usr"|"/etc"|"/var"|"/home"|"/root")
        printf '  %s✗%s refusing to delete %s\n' "$RED" "$OFF" "${dir:-<empty>}" >&2
        exit 1
        ;;
    esac
    [[ "$dir" == /* ]] || {
      printf '  %s✗%s refusing to delete a relative path: %s\n' "$RED" "$OFF" "$dir" >&2
      exit 1
    }
  done

  rm -rf "$CONFIG_DIR" "$DATA_DIR"
  userdel "$SERVICE_USER" >/dev/null 2>&1 || true
  printf '\n  %sRemoved, including all data.%s\n\n' "$GREEN" "$OFF"
else
  printf '\n  %sRemoved.%s Data was kept:\n\n' "$GREEN" "$OFF"
  printf '    %s\n    %s\n\n' "$CONFIG_DIR" "$DATA_DIR"
  printf '  Delete them later with:  rm -rf %s %s\n' "$CONFIG_DIR" "$DATA_DIR"
  printf '  Remove the account with: userdel %s\n\n' "$SERVICE_USER"
fi
