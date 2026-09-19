#!/bin/sh
# One command to set up XCast's helper. Run from a clone of the repository.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd -P)
case "$(uname -s)" in
  Darwin) exec "$HERE/install/install-macos.sh" "$@" ;;
  *) echo "XCast's installer supports macOS only for now (the helper runs in a macOS sandbox)." >&2; exit 1 ;;
esac
