#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
archive="$root/.cache/sing-box-v1.14.4.tar.gz"
digest=0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18
test "$(shasum -a 256 "$archive" | cut -d ' ' -f 1)" = "$digest"
mkdir -p "$root/.cache/windows-build" "$root/artifacts/windows"
work=$(mktemp -d "$root/.cache/windows-build/core.XXXXXXXX")
trap 'test -z "$work" || rm -rf -- "$work"' EXIT
tar -xzf "$archive" --strip-components=1 -C "$work"
cp "$root/macos/Dependencies/go.mod" "$root/macos/Dependencies/go.sum" "$work"
mkdir -p "$work/experimental/privateprofile" "$work/cmd/aliang-windows"
sed 's/^package profile$/package privateprofile/' "$root/core/profile/compile.go" > "$work/experimental/privateprofile/compile.go"
cp "$root/windows/core/"*.go "$work/cmd/aliang-windows"
mkdir -p "$work/cmd/aliang-launcher"
cp "$root/windows/launcher/main_windows.go" "$work/cmd/aliang-launcher/"
export GOTOOLCHAIN=go1.26.11
export GOMODCACHE="$root/.cache/go-mod" GOCACHE="$root/.cache/go-build"
export GOPATH="$root/.tools/go-path"
cd "$work"
core_tags=with_gvisor,with_utls,badlinkname,tfogo_checklinkname0
CGO_ENABLED=0 go test -mod=readonly -tags="$core_tags" \
  -ldflags='-checklinkname=0' ./cmd/aliang-windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -mod=readonly -trimpath \
  -tags="$core_tags" -ldflags='-checklinkname=0 -s -w' \
  -o "$work/proxy-core.exe" ./cmd/aliang-windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -mod=readonly -trimpath \
  -ldflags='-H windowsgui -s -w' -o "$work/ALiang-Proxy.exe" ./cmd/aliang-launcher
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c -mod=readonly -trimpath \
  -tags="$core_tags" -ldflags='-checklinkname=0 -s -w' \
  -o "$work/ALiang-Core-Tests-x64.exe" ./cmd/aliang-windows
mv "$work/proxy-core.exe" "$root/artifacts/windows/proxy-core.exe"
mv "$work/ALiang-Proxy.exe" "$root/artifacts/windows/ALiang-Proxy.exe"
mv "$work/ALiang-Core-Tests-x64.exe" "$root/artifacts/windows/ALiang-Core-Tests-x64.exe"
gvisor_dir=$(go list -mod=readonly -m -f '{{.Dir}}' github.com/sagernet/gvisor)
install -m 0644 "$gvisor_dir/LICENSE" "$root/artifacts/windows/LICENSE-gVisor.txt"
