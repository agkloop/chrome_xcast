#!/bin/sh
# Builds xcast-host and registers it as a Chrome native messaging host that
# only the given extension ID may launch. The helper runs inside a
# deny-by-default macOS sandbox (xcast.sb).
set -eu

EXT_ID="${1:-}"
if ! printf '%s' "$EXT_ID" | grep -Eq '^[a-p]{32}$'; then
  echo "usage: $0 <extension-id>   (32 letters a-p, from chrome://extensions)" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo "Do not run as root: the helper is a per-user install." >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
DEST="$HOME/Library/Application Support/XCast"
NMH="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
ORIGIN="chrome-extension://$EXT_ID/"
TOOLCHAIN=$(awk '$1 == "toolchain" { print $2 }' "$ROOT/host/go.mod")

# These paths end up inside JSON and a sandbox profile parameter.
case "$DEST$NMH" in
  *\"* | *\\* | *'
'*) echo "Unsupported character in home directory path." >&2; exit 1 ;;
esac

umask 077
mkdir -p "$DEST" "$DEST/data" "$NMH"
for d in "$DEST" "$DEST/data" "$NMH"; do
  # No symlinks planted by someone else, and nothing we do not own.
  if [ -L "$d" ] || [ ! -O "$d" ]; then
    echo "Refusing to install into $d (symlink or not owned by you)." >&2
    exit 1
  fi
done
chmod 700 "$DEST" "$DEST/data"
DEST=$(cd "$DEST" && pwd -P) # the sandbox matches real paths, not symlinks

GO=$(command -v go) || { echo "Go is required: https://go.dev/dl/" >&2; exit 1; }
echo "Building with $GO (toolchain $TOOLCHAIN, fetched and checksum-verified if needed)"
# Clean environment: no inherited GOFLAGS (-toolexec, -overlay), proxies or
# toolchain overrides can alter what gets compiled.
(cd "$ROOT/host" && env -i HOME="$HOME" PATH="$(dirname "$GO"):/usr/bin:/bin" \
  GOTOOLCHAIN="$TOOLCHAIN" GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  GOFLAGS=-mod=readonly CGO_ENABLED=0 \
  "$GO" build -trimpath -buildvcs=false \
  -ldflags "-s -w -X main.allowedOrigin=$ORIGIN" -o "$DEST/xcast-host.new" .)
mv -f "$DEST/xcast-host.new" "$DEST/xcast-host"
chmod 500 "$DEST/xcast-host"
# Hardened runtime: no code injection (DYLD_*), no debugger attach.
codesign --force --options runtime -s - "$DEST/xcast-host" 2>/dev/null || echo "warning: codesign failed; continuing unsigned" >&2

install -m 400 "$ROOT/install/xcast.sb" "$DEST/xcast.sb"

# Chrome starts this wrapper; it puts the helper in the sandbox.
WRAPPER="$DEST/xcast-host-sandboxed"
rm -f "$WRAPPER"
cat > "$WRAPPER" <<WRAP
#!/bin/sh
export XCAST_DATA="$DEST/data"
exec /usr/bin/sandbox-exec -D BIN="$DEST/xcast-host" -D DIR="$DEST" -D DATA="$DEST/data" -f "$DEST/xcast.sb" "$DEST/xcast-host" "\$@"
WRAP
chmod 500 "$WRAPPER"

# Refuse to install a sandbox that does not work on this macOS.
if ! "$WRAPPER" -selftest >/dev/null 2>&1; then
  echo "Sandbox self-test failed on this macOS version; not installing." >&2
  exit 1
fi

# Register with every Chrome channel that is present. Each keeps its own folder.
umask 077
for channel in "Chrome" "Chrome Beta" "Chrome Dev" "Chrome Canary"; do
  base="$HOME/Library/Application Support/Google/$channel"
  [ -d "$base" ] || continue
  dir="$base/NativeMessagingHosts"
  mkdir -p "$dir"
  if [ -L "$dir" ] || [ ! -O "$dir" ]; then
    echo "Skipping $channel: $dir is a symlink or not owned by you." >&2
    continue
  fi
  cat > "$dir/com.xcast.host.json" <<EOF2
{
  "name": "com.xcast.host",
  "description": "XCast helper",
  "path": "$WRAPPER",
  "type": "stdio",
  "allowed_origins": ["$ORIGIN"]
}
EOF2
  chmod 600 "$dir/com.xcast.host.json"
  echo "Registered: Google $channel"
done

echo "Installed:  $DEST/xcast-host"
echo "SHA-256:    $(shasum -a 256 "$DEST/xcast-host" | cut -d' ' -f1)"
echo "Allowed:    $ORIGIN"
echo "Sandbox:    active (self-test passed)"
echo "Find TVs:   \"$WRAPPER\" -discover"
