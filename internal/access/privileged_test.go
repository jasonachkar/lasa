package access

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Run by the disposable VM harness. The only write attempts target an isolated
// fixture; the scanner's production evaluator itself never attempts a write.
func TestPrivilegedDACAgainstKernel(t *testing.T) {
	if os.Getenv("LASA_ACCESS_HELPER") == "1" {
		h, e := os.OpenFile(os.Getenv("LASA_ACCESS_TARGET"), os.O_WRONLY|os.O_APPEND, 0)
		if e != nil {
			os.Exit(3)
		}
		h.Close()
		os.Exit(0)
	}
	if os.Getenv("LASA_PRIVILEGED_TESTS") != "1" {
		t.Skip("requires explicit disposable-VM authorization")
	}
	if os.Geteuid() != 0 {
		t.Fatal("authorized kernel DAC validation requires root")
	}
	dir, e := os.MkdirTemp("", "lasa-kernel-dac-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if e = os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "fixture")
	if e = os.WriteFile(path, []byte("synthetic fixture only"), 0644); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	src, e := os.Open(binary)
	if e != nil {
		t.Fatal(e)
	}
	defer src.Close()
	helper := filepath.Join(dir, "helper")
	dst, e := os.OpenFile(helper, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = io.Copy(dst, src); e != nil {
		t.Fatal(e)
	}
	if e = dst.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(helper, 0755); e != nil {
		t.Fatal(e)
	}
	none := ^uint32(0)
	cases := []struct {
		name string
		mode os.FileMode
		acl  []byte
		want bool
	}{{"protected", 0644, nil, false}, {"world_write", 0666, nil, true}, {"acl_mask_denies", 0644, aclRaw(ACLEntry{1, 6, none}, ACLEntry{2, 6, 1001}, ACLEntry{4, 4, none}, ACLEntry{16, 4, none}, ACLEntry{32, 0, none}), false}, {"acl_mask_permits", 0644, aclRaw(ACLEntry{1, 6, none}, ACLEntry{2, 6, 1001}, ACLEntry{4, 4, none}, ACLEntry{16, 6, none}, ACLEntry{32, 0, none}), true}}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_ = unix.Removexattr(path, "system.posix_acl_access")
			if e := os.Chmod(path, tt.mode); e != nil {
				t.Fatal(e)
			}
			if tt.acl != nil {
				if e := unix.Setxattr(path, "system.posix_acl_access", tt.acl, 0); e != nil {
					t.Fatal("fixture filesystem must support POSIX ACLs", e)
				}
			}
			result, e := EvaluatePath(context.Background(), path, []Account{{Name: "synthetic-uid-1001", UID: 1001, GID: 1001, Groups: []uint32{1001}}})
			if e != nil {
				t.Fatal(e)
			}
			predicted := len(result.Writers) > 0
			cmd := exec.Command(helper, "-test.run=^TestPrivilegedDACAgainstKernel$")
			cmd.Env = []string{"LASA_ACCESS_HELPER=1", "LASA_ACCESS_TARGET=" + path}
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001, Groups: []uint32{1001}}}
			actual := cmd.Run() == nil
			if predicted != tt.want || actual != tt.want {
				t.Fatalf("predicted=%t kernel=%t expected=%t", predicted, actual, tt.want)
			}
		})
	}
}
