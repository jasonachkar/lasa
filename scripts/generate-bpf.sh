#!/bin/sh
set -eu
repository=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
cd "$repository/internal/collector/ebpf"
export GOPACKAGE=ebpf
go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-19 -strip llvm-strip-19 -target bpfel \
 -cflags "-O2 -g -Wall -Werror -ffile-prefix-map=$repository=. -fdebug-compilation-dir=. ${BPF_CFLAGS:-}" \
 sensor "$repository/bpf/lasa.bpf.c"
