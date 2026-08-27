#!/usr/bin/env bash
#
# Assert that the release workflow produces what the installer downloads.
#
# install.sh and update.sh fetch release assets by name. If the two ever drift
# apart, nothing fails until someone runs an upgrade — and then it fails for
# everyone at once, on a machine the maintainer is not sitting at.
#
# This runs in CI on every pull request, and can be run by hand:
#
#   scripts/check-release-contract.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE="${ROOT}/.github/workflows/release.yml"
INSTALL="${ROOT}/scripts/install.sh"
UPDATE="${ROOT}/scripts/update.sh"

fail=0
note() { printf '  %s\n' "$*"; }
bad()  { printf '  ✗ %s\n' "$*" >&2; fail=1; }
good() { printf '  ✓ %s\n' "$*"; }

# ---------------------------------------------------------------------------
# The component list must be identical in all three places
# ---------------------------------------------------------------------------

# From install.sh: COMPONENTS="${COMPONENTS:-resolver backend portal admin}"
installer_components="$(
  grep -oE 'COMPONENTS:-[a-z ]+' "$INSTALL" | head -1 | sed 's/COMPONENTS:-//' | tr -s ' '
)"

# From release.yml: for c in resolver backend portal admin; do
release_components="$(
  grep -oE 'for c in [a-z ]+; do' "$RELEASE" | head -1 | sed -e 's/for c in //' -e 's/; do//' | tr -s ' '
)"

# From update.sh: for comp in resolver backend portal admin; do
updater_components="$(
  grep -oE 'for comp in [a-z ]+; do' "$UPDATE" | head -1 | sed -e 's/for comp in //' -e 's/; do//' | tr -s ' '
)"

note "installer: ${installer_components}"
note "updater:   ${updater_components}"
note "release:   ${release_components}"
printf '\n'

[[ -n "$installer_components" ]] || bad "could not read the component list from install.sh"
[[ -n "$release_components"   ]] || bad "could not read the component list from release.yml"
[[ -n "$updater_components"   ]] || bad "could not read the component list from update.sh"

if [[ "$installer_components" == "$release_components" ]]; then
  good "release builds exactly what the installer downloads"
else
  bad "installer wants [${installer_components}], release builds [${release_components}]"
fi

if [[ "$installer_components" == "$updater_components" ]]; then
  good "the updater agrees"
else
  bad "updater detects [${updater_components}], installer wants [${installer_components}]"
fi

# ---------------------------------------------------------------------------
# Every component must actually have a command to build
# ---------------------------------------------------------------------------

for comp in $release_components; do
  if [[ -d "${ROOT}/cmd/privatedns-${comp}" ]]; then
    good "cmd/privatedns-${comp} exists"
  else
    bad "release.yml builds ${comp}, but cmd/privatedns-${comp} does not exist"
  fi
done

# ---------------------------------------------------------------------------
# Assets the docs and scripts fetch by exact name must be published
# ---------------------------------------------------------------------------

for asset in SHA256SUMS install.sh install.sh.sha256; do
  if grep -q "$asset" "$RELEASE"; then
    good "publishes ${asset}"
  else
    bad "install.sh fetches ${asset}, which release.yml does not publish"
  fi
done

# `releases/latest/download/<name>` needs an exact asset name, so a versioned
# filename cannot be reached that way. Anything the docs promise there must be
# uploaded under that stable name.
while read -r asset; do
  [[ -n "$asset" ]] || continue
  if grep -q "$asset" "$RELEASE"; then
    good "docs reference ${asset}, and it is published"
  else
    bad "docs promise ${asset} at latest/download, but release.yml does not upload it"
  fi
done < <(
  grep -ohE 'releases/latest/download/[A-Za-z0-9_.-]+' "${ROOT}/docs/installation.md" "${ROOT}/README.md" 2>/dev/null \
    | sed 's|.*/||' | sort -u
)

# ---------------------------------------------------------------------------
# The signature the scripts verify must be the one the release signs
# ---------------------------------------------------------------------------

if grep -q 'cosign sign-blob' "$RELEASE"; then
  good "release signs SHA256SUMS"
  for f in "$INSTALL" "$UPDATE"; do
    if grep -q 'cosign verify-blob' "$f"; then
      good "$(basename "$f") verifies the signature"
    else
      bad "$(basename "$f") does not verify the signature the release produces"
    fi
  done
  for suffix in .sig .pem; do
    if grep -q "SHA256SUMS${suffix}" "$RELEASE"; then
      good "publishes SHA256SUMS${suffix}"
    else
      bad "scripts fetch SHA256SUMS${suffix}, which is not published"
    fi
  done
else
  bad "release.yml does not sign anything"
fi

printf '\n'
if [[ $fail -eq 0 ]]; then
  printf '  Release contract holds.\n\n'
else
  printf '  Release contract is BROKEN. Fix before tagging.\n\n' >&2
fi
exit $fail
