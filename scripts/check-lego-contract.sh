#!/usr/bin/env bash
#
# Assert that every lego flag issue-cert.sh passes is one lego actually accepts,
# in the position it is passed.
#
# v1.0.6 shipped a helper built for lego v4, where the ACME flags were global
# and preceded the subcommand. lego v5 moved them onto `run`, so the shipped
# command failed immediately:
#
#     Incorrect Usage: flag provided but not defined: -accept-tos
#
# Nothing in the build could notice, because lego is installed on the target
# machine and its CLI was never exercised here.
#
#   scripts/check-lego-contract.sh              # use lego from PATH
#   LEGO_BIN=/path/to/lego  scripts/...         # or a specific binary
#   DOWNLOAD_LEGO=1         scripts/...         # fetch the latest release first

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
HELPER="deploy/scripts/issue-cert.sh"

fails=0
pass()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
report() { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; fails=$((fails + 1)); }

LEGO_BIN="${LEGO_BIN:-lego}"

if [[ "${DOWNLOAD_LEGO:-}" == "1" ]] && ! command -v "$LEGO_BIN" >/dev/null 2>&1; then
  echo "==> Fetching the latest lego"
  json="$(curl -fsSL https://api.github.com/repos/go-acme/lego/releases/latest)" || {
    echo "  could not reach the GitHub API" >&2; exit 1; }
  v="${json#*\"tag_name\"}"; v="${v#*:}"; v="${v#*\"}"; v="${v%%\"*}"
  tmp="$(mktemp -d)"
  curl -fsSL "https://github.com/go-acme/lego/releases/download/${v}/lego_${v}_linux_amd64.tar.gz" \
    -o "$tmp/lego.tgz" || { echo "  download failed" >&2; exit 1; }
  tar -xzf "$tmp/lego.tgz" -C "$tmp" lego
  LEGO_BIN="$tmp/lego"
  echo "  using $v"
fi

if ! command -v "$LEGO_BIN" >/dev/null 2>&1 && [[ ! -x "$LEGO_BIN" ]]; then
  echo "  no lego binary available (set LEGO_BIN, or DOWNLOAD_LEGO=1)" >&2
  echo "  this check must run in CI, where it can" >&2
  exit 2
fi

version="$("$LEGO_BIN" --version 2>/dev/null)" || version="unknown"
echo "==> ${version}"

help_run="$("$LEGO_BIN" run --help 2>/dev/null || true)"
help_top="$("$LEGO_BIN" --help 2>/dev/null || true)"

# Where does this lego take the ACME flags?
if [[ "$help_run" == *"--accept-tos"* ]]; then
  style=subcommand
elif [[ "$help_top" == *"--accept-tos"* ]]; then
  style=global
else
  report "this lego accepts --accept-tos in neither position"
  exit 1
fi
pass "flags belong on the ${style}"

# The helper must agree about that.
if grep -q 'LEGO_STYLE' "$HELPER"; then
  pass "the helper probes for the flag position rather than assuming one"
else
  report "the helper hardcodes a flag position; it will break on the other one"
fi

# Every flag the helper passes must exist where it passes it.
accepted="$help_run
$help_top"

# Take the flags from the lego_args array itself, not from anywhere in the file
# -- the help text in this script mentions flags it never passes.
flags="$(awk '/^lego_args=\(/{inside=1; next} inside && /^\)/{inside=0} inside' "$HELPER" \
         | sed -n 's/^[[:space:]]*\(--[a-z][a-z0-9.-]*\).*/\1/p' | sort -u)"
[[ -n "$flags" ]] || { report "found no lego flags in ${HELPER}"; exit 1; }

for f in $flags; do
  if [[ "$accepted" == *"$f"* ]]; then
    pass "${f} is accepted"
  else
    report "${f} is passed by the helper but this lego does not define it"
  fi
done

# `renew` stopped being a top-level command in v5.
if [[ "$style" == "subcommand" ]]; then
  if grep -q 'ACTION=run' "$HELPER"; then
    pass "renew is mapped onto run, which is where v5 handles it"
  else
    report "the helper can still invoke a top-level 'renew', which v5 removed"
  fi
fi

echo
if [[ $fails -ne 0 ]]; then
  printf '\033[31m%d problem(s)\033[0m -- the helper and this lego disagree\n' "$fails" >&2
  exit 1
fi
printf '\033[32mhelper matches this lego\033[0m\n'
