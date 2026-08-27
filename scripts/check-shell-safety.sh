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


echo "==> Checking for early-exit readers in pipelines under pipefail"

# grep -q / grep -m / head stop reading as soon as they have what they need.
# The writer on the left is then killed by SIGPIPE, pipefail promotes 141 to
# the pipeline's status, and the result is either a fatal error or -- worse --
# a condition that quietly evaluates to false. Both shipped in v1.0.x.
for script in scripts/install.sh scripts/update.sh scripts/uninstall.sh \
              scripts/private-dns deploy/scripts/*.sh; do
  [[ -f "$script" ]] || continue
  grep -q 'pipefail' "$script" || continue

  # Strip comments (they discuss the pattern) and neutralise `||`, whose second
  # bar is not a pipe. What is left is real pipelines only.
  hits="$(sed -e 's/#.*$//' -e 's/||/__OR__/g' "$script" \
          | grep -nE '\|[[:space:]]*(grep([[:space:]]+-[A-Za-z]*[qm][A-Za-z]*)+|head([[:space:]]|$))' || true)"
  if [[ -n "$hits" ]]; then
    report "$script pipes into an early-exit reader under pipefail"
    printf '%s\n' "$hits" | sed 's/^/        /' >&2
  fi
done
[[ $fails -eq 0 ]] && pass "no pipeline can be killed by its own reader"


echo "==> Checking assignments cannot abort a script silently under set -e"

# VAR="$(cmd)" takes the exit status of the substitution. Under `set -e` a
# failing substitution kills the script AT THE ASSIGNMENT, so every check
# written below it is unreachable. issue-cert.sh died at exactly such a line
# with status 127 and no message, because the substitution's stderr went to
# /dev/null -- the validation meant to explain the problem never ran.
for script in scripts/*.sh scripts/private-dns deploy/scripts/*.sh; do
  [[ -f "$script" ]] || continue
  grep -q 'set -e' "$script" || continue

  hits="$(sed -e 's/#.*$//' "$script" \
          | grep -vF '||' | grep -nE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*="\$\(.*2>[[:space:]]*/dev/null.*\)"[[:space:]]*$' \
          || true)"
  if [[ -n "$hits" ]]; then
    report "$script assigns from a silenced substitution with no || fallback"
    printf '%s\n' "$hits" | sed 's/^/        /' >&2
  fi
done
[[ $fails -eq 0 ]] && pass "no assignment can abort a script without saying why"
echo "==> Checking the installer promises only what it installs"

# v1.0.3 told the operator to run private-dns and privatedns-issue-cert in its
# closing message. install_cli only copied those from a sibling directory, which
# exists in a git checkout and never in a standalone install -- the only
# supported path -- so it silently installed nothing and the commands were
# absent. A command named in the output must be one the installer puts there.
promised="$(grep -oE '(\$\{PREFIX\}|/usr/local/bin)/[a-z-]+|(^|[^-a-z])private-dns [a-z]' scripts/install.sh \
            | grep -oE '(private-dns|privatedns-[a-z-]+|update|uninstall)' | sort -u || true)"

for cmd in $promised; do
  case "$cmd" in
    privatedns-resolver|privatedns-backend|privatedns-portal|privatedns-admin)
      continue ;;   # release binaries, installed by install_binaries
  esac
  if grep -qE ":${cmd}\"|/${cmd}\"" scripts/install.sh; then
    pass "installs ${cmd}, which it also tells the operator to run"
  else
    report "names ${cmd} but never installs it"
  fi
done

# One source of truth for feed URLs.
if grep -qE 'hagezi|oisd|StevenBlack|dns-blocklists' scripts/install.sh; then
  report "install.sh hardcodes a blocklist URL; fetch-blocklists.sh owns those"
else
  pass "no duplicated blocklist URL in install.sh"
fi
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
