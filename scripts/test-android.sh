#!/bin/sh
set -eu
. "$(dirname -- "$0")/android-env.sh"
cd "$REPO_DIR/android/native"
TAGS=with_gvisor,with_utls,badlinkname,tfogo_checklinkname0
go test -race -ldflags=-checklinkname=0 -tags="$TAGS" ./mobile
go vet -tags="$TAGS" ./mobile
GOOS=android GOARCH=arm64 CGO_ENABLED=1 \
  CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android26-clang" \
  go list -deps -json -tags="$TAGS" ./mobile > "$REPO_DIR/.cache/android-packages.json"
go run ./cmd/verifydeps "$REPO_DIR/.cache/android-packages.json" go.sum
GOOS=android GOARCH=arm64 CGO_ENABLED=1 \
  CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android26-clang" \
  govulncheck -tags="$TAGS" ./mobile
cd "$REPO_DIR/android"
./gradlew testDebugUnitTest lintDebug assembleDebugAndroidTest --no-daemon
