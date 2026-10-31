#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-dev}"
if [[ ! "$version" =~ ^[a-zA-Z0-9._-]+$ ]]; then echo 'Invalid version' >&2; exit 2; fi
mkdir -p dist
for arch in amd64 arm64; do
  stage="dist/netkit_${version}_linux_${arch}"
  mkdir -p "$stage"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X github.com/Alifarid0011/netkit/internal/app.Version=$version" -o "$stage/netkit" ./cmd/netkit
  cp README.md LICENSE CHANGELOG.md ROADMAP.md "$stage/"
  cp packaging/install.sh "$stage/install.sh"
  chmod 755 "$stage/install.sh"
  tar -C dist -czf "${stage}.tar.gz" "$(basename "$stage")"
done
(cd dist && sha256sum "netkit_${version}_linux_amd64.tar.gz" "netkit_${version}_linux_arm64.tar.gz" > SHA256SUMS)
