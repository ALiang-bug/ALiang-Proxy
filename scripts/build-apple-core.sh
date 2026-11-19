#!/bin/sh
set -eu
REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE_DIR="$REPO_DIR/.cache/sing-box-1.14.4"
test "$(uname -s)" = Darwin || { echo 'Apple core build requires macOS and Xcode.' >&2; exit 1; }
test -f "$SOURCE_DIR/experimental/libbox/packet_service.go" || {
  echo 'Prepare the pinned upstream source with scripts/prepare-core.ps1 first (PowerShell is cross-platform).' >&2
  exit 1
}
export GOCACHE="$REPO_DIR/.cache/go-build"
export GOMODCACHE="$REPO_DIR/.cache/go-mod"
export GOPATH="$REPO_DIR/.tools/go-path"
export GOBIN="$REPO_DIR/.tools/bin"
mkdir -p "$GOBIN" "$REPO_DIR/Frameworks"
export PATH="$GOBIN:$PATH"
cd "$SOURCE_DIR"
go test -ldflags=-checklinkname=0 -tags with_gvisor,with_utls,badlinkname,tfogo_checklinkname0 ./experimental/libbox/packetbridge ./experimental/libbox -run 'Test(RoundTrip|CloseUnblocks|OverflowAndMalformed|PacketService)'
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.12
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.12
gomobile init
gomobile bind -target=ios,iossimulator -iosversion=17.0 -libname=box \
  -ldflags=-checklinkname=0 \
  -tags=with_gvisor,with_utls,with_low_memory,badlinkname,tfogo_checklinkname0 \
  -o "$REPO_DIR/Frameworks/Libbox.xcframework" ./experimental/libbox
echo 'Core built. Generate ios/project.yml with XcodeGen, then compile both iOS targets.'
