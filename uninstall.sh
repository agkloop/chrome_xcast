#!/bin/sh
# Removes XCast's helper and its registration with Chrome. The extension itself
# is removed in chrome://extensions.
set -eu
[ "$(uname -s)" = "Darwin" ] || { echo "Nothing to do: the helper is only installed on macOS." >&2; exit 0; }

DEST="$HOME/Library/Application Support/XCast"
for channel in "Chrome" "Chrome Beta" "Chrome Dev" "Chrome Canary"; do
  f="$HOME/Library/Application Support/Google/$channel/NativeMessagingHosts/com.xcast.host.json"
  if [ -f "$f" ]; then rm -f "$f"; echo "Unregistered from Google $channel"; fi
done

KEEP_PINS=yes
[ "${1:-}" = "--all" ] && KEEP_PINS=no
if [ -d "$DEST" ] && [ ! -L "$DEST" ]; then
  chmod -R u+w "$DEST" 2>/dev/null || true
  rm -f "$DEST/xcast-host" "$DEST/xcast-host-sandboxed" "$DEST/xcast.sb" "$DEST/xcast-host.new"
  if [ "$KEEP_PINS" = no ]; then
    rm -rf "$DEST/data"
    rmdir "$DEST" 2>/dev/null || true
    echo "Removed the helper and its data (remembered TVs)."
  else
    echo "Removed the helper. Remembered TVs were kept in: $DEST/data   (use --all to remove them too)"
  fi
fi
echo "To finish: remove XCast in chrome://extensions, and the \"xcast-host\" entries under"
echo "System Settings > Privacy & Security > Local Network."
