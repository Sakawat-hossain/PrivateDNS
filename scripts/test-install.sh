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
[[ -n "${CURL_FAIL:-}" ]] && exit 22
for _ in $(seq 1 400); do
  printf '  "filler": "padding so the pipe buffer cannot swallow the whole body",\n'
done
cat "${CURL_BODY:?}"
for _ in $(seq 1 400); do
  printf '  "trailer": "more padding after the interesting line",\n'
done
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

printf '{ "tag_name": "v1.0.1", "name": "release" }\n' > "$FIXTURE/release.json"
printf '{ "message": "Not Found" }\n'                   > "$FIXTURE/notfound.json"

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
if [[ $fail_n -ne 0 ]]; then
  printf '\033[31m%d failed\033[0m, %d passed\n' "$fail_n" "$pass_n" >&2
  exit 1
fi
printf '\033[32mall %d passed\033[0m\n' "$pass_n"
