#!/usr/bin/env bash
#
# Build a deployable bundle and hand it to a server.
#
# This exists for the window before the first release. install.sh downloads
# published artifacts, and until a tag has been built there is nothing to
# download — so the way to get a working install onto a VPS today is to build
# here and copy the result across.
#
#   scripts/build-for-vps.sh                      # bundle only
#   scripts/build-for-vps.sh root@your-server     # bundle and copy
#   ARCH=arm64 scripts/build-for-vps.sh root@host # for an arm server
#
# It does not install anything remotely. The bundle carries an install script
# you run yourself, after looking at it.

set -euo pipefail

ARCH="${ARCH:-amd64}"
TARGET="${1:-}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
STAGE="${DIST}/bundle"
VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"

BOLD=$'\033[1m'; GREEN=$'\033[32m'; OFF=$'\033[0m'
if [[ ! -t 1 ]]; then BOLD=''; GREEN=''; OFF=''; fi

step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }

step "Building ${VERSION} for linux/${ARCH}"

rm -rf "$STAGE"
mkdir -p "$STAGE"/{bin,systemd,configs,scripts}

# CGO off keeps the binaries static, so they run on the server whatever its
# libc situation is.
export CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH"

for c in resolver backend portal admin; do
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${STAGE}/bin/privatedns-${c}" "${ROOT}/cmd/privatedns-${c}"
  ok "privatedns-${c}"
done

cp "${ROOT}"/deploy/systemd/*.service          "${STAGE}/systemd/"
cp "${ROOT}"/configs/*.example.*               "${STAGE}/configs/"
cp "${ROOT}"/scripts/private-dns               "${STAGE}/scripts/"
cp "${ROOT}"/scripts/update.sh                 "${STAGE}/scripts/update"
cp "${ROOT}"/scripts/uninstall.sh              "${STAGE}/scripts/uninstall"
cp "${ROOT}"/deploy/scripts/issue-cert.sh      "${STAGE}/scripts/privatedns-issue-cert"
cp "${ROOT}"/deploy/scripts/fetch-blocklists.sh "${STAGE}/scripts/privatedns-fetch-blocklists"
chmod +x "${STAGE}"/scripts/* "${STAGE}"/bin/*

# The bundle's own installer. Deliberately small and readable: it places files
# and nothing else, so an operator can see exactly what it does before running
# it as root.
cat > "${STAGE}/install-bundle.sh" <<'ENDINSTALL'
#!/usr/bin/env bash
# Installs the bundle sitting beside this script. Read it, then run it.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run this with sudo" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER=privatedns
CONFIG=/etc/private-dns
DATA=/var/lib/private-dns

id -u "$USER" >/dev/null 2>&1 || \
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"

install -d -m 0755 "$CONFIG"
install -d -m 0750 -o "$USER" -g "$USER" "$CONFIG/certs" "$DATA" "$DATA/blocklists"
install -d -m 0700 -o "$USER" -g "$USER" "$DATA/backups"

install -m 0755 "$HERE"/bin/*      /usr/local/bin/
install -m 0755 "$HERE"/scripts/*  /usr/local/bin/
install -m 0644 "$HERE"/systemd/*  /etc/systemd/system/
install -m 0644 "$HERE"/configs/*  "$CONFIG/"

# Only on a first install. Re-running to update a build must not reset a token
# or a domain someone has already configured.
if [[ ! -f "$CONFIG/config.json" ]]; then
  TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  sed -e "s|GENERATE_WITH_openssl_rand_hex_32|$TOKEN|" \
      "$CONFIG/config.example.json" > "$CONFIG/config.json"
  chmod 0640 "$CONFIG/config.json"
  chown root:"$USER" "$CONFIG/config.json"
  echo ""
  echo "Resolver admin token: $TOKEN"
  echo ""
fi

systemctl daemon-reload
echo "Installed. Next:"
echo "  1. Set base_domain in $CONFIG/config.json"
echo "  2. Issue a certificate: privatedns-issue-cert run"
echo "  3. systemctl enable --now privatedns-resolver"
echo "  4. private-dns status"
ENDINSTALL
chmod +x "${STAGE}/install-bundle.sh"

TARBALL="${DIST}/privatedns-${VERSION}-linux-${ARCH}.tar.gz"
tar -czf "$TARBALL" -C "$DIST" bundle
( cd "$DIST" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

ok "$(du -h "$TARBALL" | cut -f1)  ${TARBALL}"

if [[ -z "$TARGET" ]]; then
  cat <<EOF

Copy it across and install:

  scp ${TARBALL} your-server:/tmp/
  ssh your-server
  cd /tmp && tar -xzf $(basename "$TARBALL")
  less bundle/install-bundle.sh
  sudo bash bundle/install-bundle.sh

EOF
  exit 0
fi

step "Copying to ${TARGET}"
scp "$TARBALL" "${TARGET}:/tmp/"
ok "copied"

cat <<EOF

Now, on the server:

  ssh ${TARGET}
  cd /tmp && tar -xzf $(basename "$TARBALL")
  less bundle/install-bundle.sh
  sudo bash bundle/install-bundle.sh

EOF
