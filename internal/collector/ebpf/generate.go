//go:build linux

package ebpf

// go generate is a maintainer build action, never a scan-time action.
// BPF_CFLAGS may add an explicit, trusted libbpf include directory.
//go:generate sh ../../../scripts/generate-bpf.sh
