#!/bin/sh
set -eu
. "$(dirname -- "$0")/android-env.sh"
ARCHIVE="$REPO_DIR/.cache/sing-box-v1.14.4.tar.gz"
EXPECTED=0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18
test "$(shasum -a 256 "$ARCHIVE" | cut -d ' ' -f 1)" = "$EXPECTED" || { echo 'Invalid upstream archive' >&2; exit 1; }
SOURCE_DIR="$REPO_DIR/.cache/android-sing-box-1.14.4"
if ! test -f "$SOURCE_DIR/go.mod"; then
  mkdir -p "$SOURCE_DIR"
  tar -xzf "$ARCHIVE" -C "$SOURCE_DIR" --strip-components=1
fi
cd "$REPO_DIR/android/native"
TAGS=with_gvisor,with_utls,with_low_memory,badlinkname,tfogo_checklinkname0
go test -ldflags=-checklinkname=0 -tags="$TAGS" ./mobile
gomobile bind -target=android/arm64,android/amd64 -androidapi=26 \
  -javapkg=local.aliang.core -libname=aliang -trimpath \
  -ldflags='-checklinkname=0 -s -w' -tags="$TAGS" \
  -o ../app/libs/aliang-core.aar ./mobile
shasum -a 256 ../app/libs/aliang-core.aar > ../app/libs/aliang-core.aar.sha256
