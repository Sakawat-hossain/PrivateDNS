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

# Hagezi "light" and StevenBlack "unified": both actively curated with low
# false-positive rates, which matters more than raw list size. A blocked bank
# login costs more support time than a hundred unblocked trackers.
#
# Two things about these URLs are load-bearing, and both were got wrong once:
#
#   - The path must exist. v1.0.2 shipped hagezi's "domains/light.txt", which
#     404s; the directory is "wildcard/". Run this script with --check to test
#     every URL without installing anything.
#
#   - It must be the plain-domain edition. hagezi publishes "light.txt" (entries
#     written as *.example.com) beside "light-onlydomains.txt", and the resolver
#     drops any line containing a "*". The wildcard file therefore downloads
#     fine, passes the size check, and blocks nothing whatsoever.
declare -A FEEDS=(
  [hagezi-light]="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"
  [stevenblack-unified]="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
)

# --check tests every feed URL and its format without touching $DEST. Run it
# after changing a URL, and from cron if you want to hear about a feed that has
# moved before it silently stops updating.
if [[ "${1:-}" == "--check" ]]; then
  rc=0
  for name in "${!FEEDS[@]}"; do
    url="${FEEDS[$name]}"
    if ! curl -fsSL --max-time 120 "$url" -o "$TMP/$name.txt"; then
      echo "  FAIL  $name  cannot fetch $url" >&2
      rc=1
      continue
    fi

    lines=$(wc -l < "$TMP/$name.txt")
    # Lines the resolver will actually keep: not blank, not a comment, and
    # without a "*", which it drops.
    usable=$(grep -cvE '^[[:space:]]*($|#|!)' "$TMP/$name.txt" || true)
    starred=$(grep -c '\*' "$TMP/$name.txt" || true)

    if (( lines < 1000 )); then
      echo "  FAIL  $name  only $lines lines" >&2
      rc=1
    elif (( starred > usable / 2 )); then
      echo "  FAIL  $name  $starred of $usable entries carry a '*'; the resolver drops those" >&2
      echo "        use the plain-domain edition of this list" >&2
      rc=1
    else
      echo "  ok    $name  $usable usable entries"
    fi
  done
  exit $rc
fi

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
