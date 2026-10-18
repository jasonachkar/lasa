#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
for arch in amd64 arm64; do
  for pass in 1 2; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X github.com/jasonachkar/lasa/internal/domain.Version=${VERSION:-0.1.0-dev}" -o "$tmp/lasa-$arch-$pass" ./cmd/lasa
  done
  cmp "$tmp/lasa-$arch-1" "$tmp/lasa-$arch-2"
  printf '%s\n' "linux/$arch repeated build bytes match"
done
