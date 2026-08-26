#!/usr/bin/env bash
# Refresh the blocklist feeds. The resolver re-reads this directory every
# fifteen minutes on its own, so this script never needs to restart anything.
#
# Run from cron, e.g. daily at 04:00:
#   0 4 * * * /usr/local/bin/fetch-blocklists.sh

set -euo pipefail

DEST="${BLOCKLIST_DIR:-/var/lib/private-dns/blocklists}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hagezi "multi light" and OISD small: both actively curated with low
# false-positive rates, which matters more than raw list size. A blocked bank
# login costs more support time than a hundred unblocked trackers.
declare -A FEEDS=(
  [hagezi-multi-light]="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"
  [oisd-small]="https://small.oisd.nl/domainswild2"
)

for name in "${!FEEDS[@]}"; do
  url="${FEEDS[$name]}"
  echo "fetching $name"
  if curl -fsSL --max-time 120 "$url" -o "$TMP/$name.txt"; then
    # Refuse to install a suspiciously small list — a truncated download would
    # otherwise silently disable most filtering.
    lines=$(wc -l < "$TMP/$name.txt")
    if (( lines < 1000 )); then
      echo "  $name returned only $lines lines, skipping" >&2
      continue
    fi
    mv "$TMP/$name.txt" "$DEST/$name.txt"
    echo "  installed $lines domains"
  else
    echo "  $name failed, keeping the previous copy" >&2
  fi
done

echo "blocklists in $DEST:"
wc -l "$DEST"/*.txt 2>/dev/null || true
