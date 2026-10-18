#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist/licenses
install -m 0644 LICENSE dist/licenses/LASA-LICENSE
install -m 0644 THIRD_PARTY_NOTICES.md dist/licenses/THIRD_PARTY_NOTICES.md
install -m 0644 bpf/libbpf-NOTICES.txt dist/licenses/libbpf-build-headers-NOTICES.txt
install -m 0644 "$(go env GOROOT)/LICENSE" dist/licenses/Go-LICENSE
for module in github.com/cilium/ebpf github.com/spf13/cobra github.com/spf13/pflag golang.org/x/sys gopkg.in/yaml.v3; do
  directory=$(go list -m -f '{{.Dir}}' "$module")
  label=$(printf '%s' "$module" | tr '/.' '--')
  if [ -f "$directory/LICENSE" ]; then install -m 0644 "$directory/LICENSE" "dist/licenses/$label-LICENSE"; else install -m 0644 "$directory/LICENSE.txt" "dist/licenses/$label-LICENSE"; fi
  if [ -f "$directory/NOTICE" ]; then install -m 0644 "$directory/NOTICE" "dist/licenses/$label-NOTICE"; fi
done
