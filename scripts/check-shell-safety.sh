#!/usr/bin/env bash
#
# Guards against a class of bug that shellcheck does not catch and that only
# shows up on a real machine.
#
# /etc/os-release is a shell fragment that assigns NAME, VERSION, ID and
# friends. Sourcing it with `.` into a script's own shell silently overwrites
# any variable of the same name. v1.0.0 shipped with exactly that: the
# installer's VERSION became "12 (bookworm)" on Debian, and the release
# download URL turned into a path with a space in it.
#
# Run from CI and before cutting a release.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fails=0
report() { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; fails=$((fails + 1)); }
pass()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }

# Variables /etc/os-release is documented to set (os-release(5)).
OS_RELEASE_VARS="NAME VERSION ID ID_LIKE VERSION_ID VERSION_CODENAME PRETTY_NAME
                 CPE_NAME HOME_URL SUPPORT_URL BUG_REPORT_URL BUILD_ID VARIANT
                 VARIANT_ID LOGO ANSI_COLOR DOCUMENTATION_URL"

echo "==> Checking for os-release variable capture"

for script in scripts/*.sh scripts/private-dns deploy/scripts/*.sh deploy/debian/postinst; do
  [[ -f "$script" ]] || continue

  # A bare `. /etc/os-release` or `source /etc/os-release` at the start of a
  # line leaks every one of those names into the caller. Reading the file
  # inside $( ... ) is fine -- the assignments die with the subshell.
  if grep -nE '^[[:space:]]*(\.|source)[[:space:]]+/etc/os-release' "$script" >/dev/null; then
    report "$script sources /etc/os-release into its own shell"
    grep -nE '^[[:space:]]*(\.|source)[[:space:]]+/etc/os-release' "$script" | sed 's/^/        /' >&2
    continue
  fi

  # If it reads os-release at all, no variable it assigns may share a name.
  if grep -q '/etc/os-release' "$script"; then
    for var in $OS_RELEASE_VARS; do
      if grep -nE "^[[:space:]]*(export[[:space:]]+)?${var}=" "$script" >/dev/null; then
        report "$script reads /etc/os-release and also assigns \$${var}"
        fails=$((fails))
      fi
    done
  fi
done

[[ $fails -eq 0 ]] && pass "no script can have its variables clobbered by /etc/os-release"

echo "==> Checking release tags are validated before use in a URL"

if grep -q 'is not a valid release tag' scripts/install.sh && grep -q 'is not a valid release tag' scripts/update.sh; then
  pass "install.sh and update.sh validate the tag before building a download URL"
else
  report "a script interpolates a version into a URL without validating it"
fi

echo
if [[ $fails -ne 0 ]]; then
  printf '\033[31m%d problem(s)\033[0m\n' "$fails" >&2
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
