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
# ---------------------------------------------------------------------------
# Every unit must start a binary that exists, with a config the installer writes
# ---------------------------------------------------------------------------
#
# v1.0.2 installed cleanly and then failed to start: the resolver unit passed
# -config /etc/private-dns/config.yaml while the installer wrote config.json.
# Nothing in the build could notice, because a systemd unit is just a text file
# until systemd reads it on the target machine.

printf '\n'
note "Units against the installer"

for unit in "${ROOT}"/deploy/systemd/privatedns-*.service; do
  unit_name="$(basename "$unit")"
  exec_line="$(grep -m1 '^ExecStart=' "$unit" | sed 's/^ExecStart=//')" || true

  binary="${exec_line%% *}"
  bin_base="$(basename "$binary")"

  if [[ -d "${ROOT}/cmd/${bin_base}" ]]; then
    good "${unit_name} starts ${bin_base}, which is built"
  else
    bad "${unit_name} starts ${bin_base}, which has no cmd/ directory"
  fi

  # Pull the -config argument out of ExecStart, if there is one.
  cfg=""
  read -ra parts <<< "$exec_line"
  for i in "${!parts[@]}"; do
    if [[ "${parts[$i]}" == "-config" || "${parts[$i]}" == "--config" ]]; then
      cfg="${parts[$((i + 1))]:-}"
      break
    fi
  done

  [[ -n "$cfg" ]] || continue
  cfg_base="$(basename "$cfg")"

  # Written literally by name, or by the backend/portal/admin loop.
  cfg_ok=0
  if grep -qE "cat > .*CONFIG_DIR.*/${cfg_base}" "$INSTALL"; then
    cfg_ok=1
  elif [[ "$cfg_base" =~ ^(backend|portal|admin)\.yaml$ ]] &&
       grep -qE 'CONFIG_DIR\}/\$\{comp\}\.yaml' "$INSTALL"; then
    cfg_ok=1
  fi

  if [[ $cfg_ok -eq 1 ]]; then
    good "${unit_name} reads ${cfg_base}, which the installer writes"
  else
    bad "${unit_name} reads ${cfg_base}, which the installer never creates"
  fi
done


printf '\n'
note "Referenced example configs exist"

# config.example.json was deleted in v1.0.3 because having two examples in two
# formats is what let the unit and the installer disagree. Two scripts still
# named it. A reference to a file that is not in the tree is a packaging
# failure that only shows up on the target machine.
for src in "${ROOT}/deploy/debian/postinst" "${ROOT}/scripts/build-for-vps.sh" \
           "${ROOT}/Dockerfile" "${ROOT}/deploy/debian/build-deb.sh"; do
  [[ -f "$src" ]] || continue
  while read -r ref; do
    [[ -n "$ref" ]] || continue
    if [[ -f "${ROOT}/configs/${ref}" ]]; then
      good "$(basename "$src") uses ${ref}, which exists"
    else
      bad "$(basename "$src") references configs/${ref}, which is not in the tree"
    fi
  done < <(grep -oE '[a-z]+\.example\.(yaml|json)' "$src" | sort -u)
done


printf '\n'
note "Admin paths the scripts call"

# private-dns and install.sh both asked for /readyz, which was never a route --
# only /ready was. curl -f turned the 404 into a connection-style failure, so
# `private-dns status` reported "the admin endpoint is not answering" about a
# perfectly healthy resolver, while reading its certificate in the next line.
registered="$(grep -oE 'mux\.HandleFunc\("[A-Z]+ [^"]+"' "${ROOT}/resolver/admin.go" \
              | sed 's/.*"[A-Z]* //; s/"$//' | sort -u)"

called="$(grep -rhoE '127\.0\.0\.1:8053/[a-z0-9/{}_-]*' \
            "${ROOT}/scripts/" "${ROOT}/deploy/" 2>/dev/null \
          | sed 's|.*:8053||' | sort -u)"

for path in $called; do
  [[ -n "$path" && "$path" != "/" ]] || continue
  if printf '%s\n' "$registered" | grep -qxF "$path"; then
    good "${path} is a registered route"
  else
    bad "${path} is called but the resolver registers no such route"
  fi
done


printf '\n'
note "Fatal errors are logged as errors"

# slog.SetDefault routes the standard log package through slog at INFO level,
# so every log.Fatalf after it prints as level=INFO. An operator ran
# -create-admin, saw INFO, assumed the account existed, and could not sign in.
for src in "${ROOT}"/cmd/*/main.go; do
  set_line="$(grep -n 'slog.SetDefault' "$src" | cut -d: -f1 | head -1)"
  [[ -n "$set_line" ]] || continue

  bad_calls="$(awk -v s="$set_line" 'NR > s && /log\.Fatal/ { print NR ": " $0 }' "$src")"
  if [[ -n "$bad_calls" ]]; then
    bad "$(basename "$(dirname "$src")") uses log.Fatal after slog.SetDefault; it will print as INFO"
    printf '%s\n' "$bad_calls" | sed 's/^/        /' >&2
  else
    good "$(basename "$(dirname "$src")") reports fatal errors at ERROR level"
  fi
done

if [[ $fail -eq 0 ]]; then
  printf '  Release contract holds.\n\n'
else
  printf '  Release contract is BROKEN. Fix before tagging.\n\n' >&2
fi
exit $fail
