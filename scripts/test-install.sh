#!/usr/bin/env bash
#
# Exercise install.sh's preflight against stubbed curl, ss and systemctl.
#
# v1.0.0 shipped an installer that could not install, and v1.0.1 fixed one bug
# while leaving a second of the same kind in place. Both were found by a user
# running it on a real machine, because nothing here ever executed the code --
# `bash -n` parses a script, it does not run it, and shellcheck does not model
# SIGPIPE under `set -o pipefail`.
#
# These tests source install.sh (its main is guarded) and call the functions.
#
#   scripts/test-install.sh

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
INSTALL_SH="${INSTALL_SH:-$PWD/scripts/install.sh}"

STUB="$(mktemp -d)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf "$STUB" "$FIXTURE"' EXIT

pass_n=0 fail_n=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; pass_n=$((pass_n + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; fail_n=$((fail_n + 1)); }

# --- stubs ----------------------------------------------------------------
# curl echoes whatever CURL_BODY names; ss echoes SS_OUT. Both write a lot of
# output, because the bugs being tested only appear when the writer is still
# writing after the reader has gone away.

cat > "$STUB/curl" <<'EOF'
#!/usr/bin/env bash
# Honour -o, because the installer uses it and a stub that ignores it tests
# nothing. Everything else on the command line is irrelevant here.
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *)  shift ;;
  esac
done

emit() {
  if [[ -n "${CURL_RAW:-}" ]]; then
    cat "${CURL_BODY:?}"
    return
  fi
  # Padding on both sides: these bugs only appear when the writer is still
  # writing after the reader has stopped.
  for _ in $(seq 1 400); do
    printf '  "filler": "padding so the pipe buffer cannot swallow the whole body",\n'
  done
  cat "${CURL_BODY:?}"
  for _ in $(seq 1 400); do
    printf '  "trailer": "more padding after the interesting line",\n'
  done
}

[[ -n "${CURL_FAIL:-}" ]] && exit 22

if [[ -n "$out" ]]; then emit > "$out"; else emit; fi
EOF

cat > "$STUB/ss" <<'EOF'
#!/usr/bin/env bash
[[ -z "${SS_OUT:-}" ]] && exit 0
for _ in $(seq 1 400); do
  printf 'LISTEN 0 4096 127.0.0.53%%lo:53 0.0.0.0:* users:(("systemd-resolve"))\n'
done
EOF

cat > "$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "is-active" ]] && exit 0
exit 0
EOF

chmod +x "$STUB"/curl "$STUB"/ss "$STUB"/systemctl
cat > "$STUB/chown" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$STUB/chmod" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$STUB"/chown "$STUB"/chmod

printf '{ "tag_name": "v1.0.1", "name": "release" }\n' > "$FIXTURE/release.json"
printf '{ "message": "Not Found" }\n'                   > "$FIXTURE/notfound.json"
printf '#!/usr/bin/env bash
echo stub
'                > "$FIXTURE/script.sh"

cat > "$FIXTURE/os-release-debian" <<'EOF'
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
EOF

# --- harness --------------------------------------------------------------
# Each case runs in its own bash so that install.sh's `set -euo pipefail` and
# any exit from fail() are contained, and so one case cannot leak state to the
# next. stdout and stderr are captured; the exit status is what is asserted.

run_case() {
  local script="$1"; shift
  env PATH="$STUB:$PATH" "$@" bash -c "
    source '$INSTALL_SH'
    $script
  " 2>&1
}

echo "==> resolve_version"

out="$(run_case 'resolve_version; echo "TAG=$RELEASE_TAG"' CURL_BODY="$FIXTURE/release.json")"
rc=$?
if [[ $rc -eq 0 && "$out" == *"TAG=v1.0.1"* ]]; then
  ok "resolves the latest tag from the API"
else
  bad "resolve_version failed (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# The regression that reached a user: curl is still writing when the reader
# stops, and pipefail promotes that to a fatal error.
if [[ "$out" == *"(23)"* || "$out" == *"Failure writing"* ]]; then
  bad "curl died on a closed pipe -- the v1.0.1 bug is back"
else
  ok "no broken-pipe failure while reading the API"
fi

out="$(run_case 'resolve_version; echo "TAG=$RELEASE_TAG"' \
        CURL_BODY="$FIXTURE/release.json" VERSION="v0.9.9")"
[[ "$out" == *"TAG=v0.9.9"* ]] \
  && ok "VERSION overrides the API lookup" \
  || bad "VERSION override ignored: $out"

out="$(run_case 'resolve_version' CURL_BODY="$FIXTURE/notfound.json")"
[[ $? -ne 0 ]] \
  && ok "a response with no tag_name fails instead of continuing" \
  || bad "accepted a response with no tag_name"

out="$(run_case 'resolve_version' CURL_BODY="$FIXTURE/release.json" CURL_FAIL=1)"
[[ $? -ne 0 ]] \
  && ok "an unreachable API fails" \
  || bad "carried on after the API call failed"

# The v1.0.0 bug, asserted directly.
out="$(run_case "check_os() { . '$FIXTURE/os-release-debian'; }
                 check_os; resolve_version; echo \"TAG=\$RELEASE_TAG\"" \
        CURL_BODY="$FIXTURE/release.json")"
if [[ "$out" == *"TAG=v1.0.1"* ]]; then
  ok "os-release cannot reach the tag even when sourced outright"
else
  bad "os-release clobbered the tag -- the v1.0.0 bug is back: $out"
fi

out="$(run_case 'resolve_version' CURL_BODY="$FIXTURE/release.json" VERSION="12 (bookworm)")"
if [[ $? -ne 0 && "$out" == *"not a valid release tag"* ]]; then
  ok "a tag with a space is rejected by name, not by curl"
else
  bad "a tag with a space was not rejected clearly: $out"
fi

echo "==> check_ports"

out="$(run_case 'check_ports')"
rc=$?
if [[ $rc -eq 0 && "$out" == *"are free"* ]]; then
  ok "reports free ports"
else
  bad "check_ports failed on a clean host (rc=$rc): $out"
fi

# The latent bug: this path only runs when a port is actually busy, so a host
# with free ports -- like the one v1.0.1 was tested on -- never reaches it.
out="$(printf 'y\n' | run_case 'check_ports' SS_OUT=1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *"in use already"* ]]; then
  ok "a busy port is reported as busy"
else
  bad "busy port not reported (rc=$rc) -- silently seen as free"; printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

out="$(printf 'n\n' | run_case 'check_ports' SS_OUT=1)"
[[ $? -ne 0 ]] \
  && ok "declining at the busy-port prompt stops the install" \
  || bad "answering no did not stop the install"

echo
echo "==> write_configs"

CFGDIR="$(mktemp -d)"; DATADIR="$(mktemp -d)"
out="$(run_case 'write_configs' CONFIG_DIR="$CFGDIR" DATA_DIR="$DATADIR" \
        SERVICE_USER="$(id -un)" COMPONENTS="resolver backend portal admin")"
if [[ -f "$CFGDIR/config.yaml" ]]; then
  ok "writes config.yaml"
else
  bad "no config.yaml written: $out"
fi

# The resolver unit names config.yaml. Anything else and the service starts,
# fails to find its configuration, and exits -- which is how v1.0.2 shipped.
unit_cfg="$(grep -m1 '^ExecStart=' deploy/systemd/privatedns-resolver.service \
            | grep -oE '\-config [^ ]+' | awk '{print $2}')"
if [[ -f "$unit_cfg" || -f "$CFGDIR/$(basename "$unit_cfg")" ]]; then
  ok "the file the resolver unit names is the file the installer writes"
else
  bad "unit reads $(basename "$unit_cfg"); installer wrote $(ls "$CFGDIR" | tr '\n' ' ')"
fi

if grep -q 'admin_tokens' "$CFGDIR/config.yaml" 2>/dev/null &&
   grep -qE '^\s+- "[0-9a-f]{64}"' "$CFGDIR/config.yaml"; then
  ok "an admin token is generated into it"
else
  bad "no admin token in config.yaml"
fi

for c in backend portal admin; do
  [[ -f "$CFGDIR/$c.yaml" ]] || bad "no $c.yaml written"
done
ok "backend, portal and admin configs written"

# A v1.0.x install has config.json. It must not be left looking authoritative.
CFGDIR2="$(mktemp -d)"
printf '{"base_domain":"old.example.com"}\n' > "$CFGDIR2/config.json"
out="$(run_case 'write_configs' CONFIG_DIR="$CFGDIR2" DATA_DIR="$DATADIR" \
        SERVICE_USER="$(id -un)" COMPONENTS="resolver")"
if [[ -f "$CFGDIR2/config.yaml" && -f "$CFGDIR2/config.json.unused" && ! -f "$CFGDIR2/config.json" ]]; then
  ok "a stale config.json is set aside, not left to look live"
else
  bad "stale config.json not handled: $(ls "$CFGDIR2" | tr '\n' ' ')"
fi

# Re-running must not mint a new admin token over a working one.
before="$(grep -oE '[0-9a-f]{64}' "$CFGDIR/config.yaml" | head -1)"
run_case 'write_configs' CONFIG_DIR="$CFGDIR" DATA_DIR="$DATADIR" \
  SERVICE_USER="$(id -un)" COMPONENTS="resolver" >/dev/null
after="$(grep -oE '[0-9a-f]{64}' "$CFGDIR/config.yaml" | head -1)"
[[ -n "$before" && "$before" == "$after" ]] \
  && ok "re-running leaves an existing config and its token alone" \
  || bad "re-running changed the admin token"

rm -rf "$CFGDIR" "$CFGDIR2" "$DATADIR"

echo "==> install_cli"

# The standalone case: no sibling checkout to copy from. v1.0.3 installed
# nothing at all here, while its closing message told the operator to run
# private-dns and privatedns-issue-cert.
BINDIR="$(mktemp -d)"; WORKDIR="$(mktemp -d)"
run_case "SCRIPT_DIR='$WORKDIR'; WORK='$WORKDIR'; RELEASE_TAG=v1.0.3; install_cli" \
  PREFIX="$BINDIR" CURL_BODY="$FIXTURE/script.sh" CURL_RAW=1 >/dev/null 2>&1

missing=""
for c in private-dns update uninstall privatedns-issue-cert privatedns-fetch-blocklists; do
  [[ -x "$BINDIR/$c" ]] || missing="$missing $c"
done
if [[ -z "$missing" ]]; then
  ok "installs every management command with no checkout present"
else
  bad "not installed:$missing"
fi
rm -rf "$BINDIR" "$WORKDIR"

echo "==> next_steps"

out="$(run_case 'RESOLVER_UP=1; next_steps')"
[[ "$out" == *"The resolver is running"* && "$out" != *"not running"* ]] \
  && ok "reports success when the resolver started" \
  || bad "wrong summary for a running resolver"

# v1.0.2 announced "PrivateDNS is running" directly under a failure notice.
out="$(run_case 'RESOLVER_UP=0; next_steps')"
if [[ "$out" == *"not running"* && "$out" == *"journalctl"* ]]; then
  ok "says so plainly when the resolver did not start"
else
  bad "claimed success after a failed start"
fi

echo
if [[ $fail_n -ne 0 ]]; then
  printf '\033[31m%d failed\033[0m, %d passed\n' "$fail_n" "$pass_n" >&2
  exit 1
fi
printf '\033[32mall %d passed\033[0m\n' "$pass_n"
