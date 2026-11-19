#!/bin/sh
set -eu
. "$(dirname -- "$0")/android-env.sh"
sh "$REPO_DIR/scripts/build-android-core.sh"
test -f "$REPO_DIR/private/android-signing.p12" || { echo 'Prepare private/android-signing.p12 and ANDROID_SIGNING_PASSWORD before release signing.' >&2; exit 1; }
test -n "${ANDROID_SIGNING_PASSWORD:-}" || { echo 'ANDROID_SIGNING_PASSWORD is required.' >&2; exit 1; }
cd "$REPO_DIR/android"
./gradlew assembleRelease testReleaseUnitTest lintRelease --no-daemon
OUTPUT="$REPO_DIR/artifacts/android"
mkdir -p "$OUTPUT"
cp app/build/outputs/apk/release/app-release.apk "$OUTPUT/ALiang-Proxy-Android.apk"
"$ANDROID_HOME/build-tools/36.0.0/apksigner" verify --verbose --print-certs "$OUTPUT/ALiang-Proxy-Android.apk" > "$OUTPUT/signature.txt"
cd "$OUTPUT"
shasum -a 256 ALiang-Proxy-Android.apk > SHA256SUMS
