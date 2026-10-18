#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.sorted"' EXIT HUP INT TERM
go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./cmd/lasa | sed '/^$/d' | sort -u > "$tmp"
sort -u tools/dependencies.allow > "$tmp.sorted"
diff -u "$tmp.sorted" "$tmp"
go mod verify
