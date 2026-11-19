#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
BUILD="$ROOT/.cache/native-installer"
mkdir -p "$BUILD" "$ROOT/macos/Resources"
# The expected core hash is compiled into the installer, not supplied at runtime.
DIGEST=$(shasum -a 256 "$ROOT/macos/Resources/proxy-core" | awk '{print $1}')
printf 'enum InstallerBuild { static let expectedSHA256 = "%s" }\n' "$DIGEST" > "$BUILD/InstallerBuild.swift"
xcrun swiftc -O -target arm64-apple-macos26.0 -module-cache-path "$BUILD/modules" \
  "$ROOT/macos/Installer/HelperInstaller.swift" "$BUILD/InstallerBuild.swift" "$ROOT/macos/Installer/main.swift" \
  -o "$ROOT/macos/Resources/install-tun-helper"
codesign --force --sign - "$ROOT/macos/Resources/install-tun-helper"
shasum -a 256 "$ROOT/macos/Resources/install-tun-helper" | awk '{print $1}' > "$ROOT/macos/Resources/install-tun-helper.sha256"
echo 'Built native macOS TUN installer.'
