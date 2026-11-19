#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$root/windows/build-core.sh"
output="$root/artifacts/windows"
stage=$(mktemp -d "$root/.cache/windows-build/package.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
for name in ALiang-Proxy.ps1 SystemProxy.ps1 NodeTests.ps1 Test-Core.ps1 Test-SystemProxy.ps1 Test-Tunnel.ps1 Test-Offline.ps1 README.md; do
  cp "$root/windows/$name" "$stage/"
done
cp "$output/ALiang-Proxy.exe" "$output/proxy-core.exe" "$output/LICENSE-gVisor.txt" "$stage/"
tar -xOf "$root/.cache/sing-box-v1.14.4.tar.gz" sing-box-1.14.4/LICENSE > "$stage/LICENSE-sing-box.txt"
(
  cd "$stage"
  zip -9 ALiang-Proxy-Windows-x64-preview.zip ALiang-Proxy.exe proxy-core.exe \
    ALiang-Proxy.ps1 SystemProxy.ps1 NodeTests.ps1 Test-Core.ps1 Test-SystemProxy.ps1 Test-Tunnel.ps1 Test-Offline.ps1 README.md LICENSE-sing-box.txt LICENSE-gVisor.txt
  unzip -t ALiang-Proxy-Windows-x64-preview.zip
)
mkdir "$stage/installer"
cp "$root/windows/installer/"*.go "$stage/installer/"
cp "$root/macos/Dependencies/go.mod" "$root/macos/Dependencies/go.sum" "$stage/installer/"
cp "$stage/ALiang-Proxy-Windows-x64-preview.zip" "$stage/installer/payload.zip"
(
  cd "$stage/installer"
  GOTOOLCHAIN=go1.26.11 GOMODCACHE="$root/.cache/go-mod" GOCACHE="$root/.cache/go-build" \
    GOPATH="$root/.tools/go-path" CGO_ENABLED=0 go test -mod=readonly -v .
  GOTOOLCHAIN=go1.26.11 GOMODCACHE="$root/.cache/go-mod" GOCACHE="$root/.cache/go-build" \
    GOPATH="$root/.tools/go-path" CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -mod=readonly -trimpath -ldflags='-H windowsgui -s -w' -o "$stage/ALiang-Proxy-Setup-x64.exe" .
)
(
  cd "$stage"
  cp "$output/ALiang-Core-Tests-x64.exe" ./
  shasum -a 256 ALiang-Proxy-Windows-x64-preview.zip ALiang-Proxy-Setup-x64.exe \
    ALiang-Core-Tests-x64.exe > SHA256SUMS
)
for path in "$stage/"*; do
  if test -f "$path"; then cp "$path" "$output/"; fi
done
