#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
export PATH="/opt/homebrew/opt/go@1.25/bin:/opt/homebrew/bin:$PATH"
export GOCACHE="$ROOT/.cache/go-build" GOMODCACHE="$ROOT/.cache/go-mod" GOPATH="$ROOT/.tools/go-path"
BASE="$ROOT/.cache/sing-box-1.14.4"
test -d "$BASE" || python3 "$ROOT/scripts/prepare-core.py"
SOURCE="$ROOT/.cache/sing-box-macos-1.14.4"
if ! test -d "$SOURCE"; then
  python3 - "$BASE" "$SOURCE" <<'COPY'
import shutil, sys
shutil.copytree(sys.argv[1], sys.argv[2])
COPY
fi
export GOTOOLCHAIN=go1.26.11
cp "$ROOT/macos/Dependencies/go.mod" "$SOURCE/go.mod"
cp "$ROOT/macos/Dependencies/go.sum" "$SOURCE/go.sum"
mkdir -p "$SOURCE/experimental/privateprofile" "$SOURCE/cmd/privateproxy-desktop" "$ROOT/macos/Resources"
sed 's/^package profile$/package privateprofile/' "$ROOT/core/profile/compile.go" > "$SOURCE/experimental/privateprofile/compile.go"
cp "$ROOT/macos/Core/"*.go "$SOURCE/cmd/privateproxy-desktop/"
(cd "$SOURCE" && go build -ldflags='-checklinkname=0 -s -w' -tags=with_utls,badlinkname,tfogo_checklinkname0 -o "$ROOT/macos/Resources/proxy-core" ./cmd/privateproxy-desktop)
(cd "$SOURCE" && DESKTOP_CORE="$ROOT/macos/Resources/proxy-core" go test -v -ldflags=-checklinkname=0 -tags=with_utls,badlinkname,tfogo_checklinkname0 ./cmd/privateproxy-desktop)
sh "$ROOT/scripts/test-macos-safety.sh"
sh "$ROOT/scripts/test-native-installer.sh"
sh "$ROOT/scripts/scan-macos.sh"
codesign --force --sign - "$ROOT/macos/Resources/proxy-core"
shasum -a 256 "$ROOT/macos/Resources/proxy-core" | awk '{print $1}' > "$ROOT/macos/Resources/proxy-core.sha256"
sh "$ROOT/scripts/build-macos-installer.sh"
sh "$ROOT/scripts/build-macos-icon.sh"
xcodegen generate --spec "$ROOT/macos/project.yml"
xcodebuild -project "$ROOT/macos/PrivateProxyMac.xcodeproj" -scheme PrivateProxyMac -configuration Debug -derivedDataPath "$ROOT/.cache/MacDerivedData" CODE_SIGNING_ALLOWED=NO build
APP="$ROOT/.cache/MacDerivedData/Build/Products/Debug/PrivateProxyMac.app"
codesign --verify "$APP/Contents/Resources/proxy-core"
codesign --force --deep --sign - "$APP"
echo "Built: $APP"
