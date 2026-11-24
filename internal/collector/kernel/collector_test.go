package kernel

import (
	"context"
	"io/fs"
	"strings"
	"testing"
)

type unavailable struct{}

func (unavailable) Read(string) ([]byte, error)               { return nil, fs.ErrPermission }
func (unavailable) Readlink(string) (string, error)           { return "", fs.ErrPermission }
func (unavailable) Names(string, int) ([]string, bool, error) { return nil, false, fs.ErrPermission }
func TestUnknownControls(t *testing.T) {
	b := (Collector{Proc: unavailable{}, Sys: unavailable{}, HostID: "h"}).Collect(context.Background())
	if b.Coverage.Complete || len(b.Controls) != 12 {
		t.Fatal("controls not represented")
	}
	for _, o := range b.Observations {
		if o.State != "unknown" {
			t.Fatal("inaccessible control deemed secure")
		}
	}
}

// fake models a kernel interface: files map to contents and dirs list entries.
type fake struct {
	files map[string]string
	dirs  map[string][]string
	err   map[string]error
}

func (f fake) Read(p string) ([]byte, error) {
	if e, ok := f.err[p]; ok {
		return nil, e
	}
	if v, ok := f.files[p]; ok {
		return []byte(v), nil
	}
	return nil, fs.ErrNotExist
}
func (fake) Readlink(string) (string, error) { return "", fs.ErrNotExist }
func (f fake) Names(p string, limit int) ([]string, bool, error) {
	names, ok := f.dirs[p]
	if !ok {
		return nil, false, fs.ErrNotExist
	}
	return names[:min(limit, len(names))], len(names) > limit, nil
}

func TestAbsentControlsAreNotApplicableOnlyWithVisibleWitness(t *testing.T) {
	proc := fake{
		files: map[string]string{
			"sys/kernel/yama/ptrace_scope": "1\n", "sys/kernel/kptr_restrict": "1", "sys/kernel/dmesg_restrict": "0",
			"sys/kernel/unprivileged_bpf_disabled": "2", "sys/user/max_user_namespaces": "100",
		},
		dirs: map[string][]string{"sys/kernel": {"yama"}, "sys/user": {"max_user_namespaces"}, "sys/net/core": {"somaxconn"}},
		err:  map[string]error{"sys/net/core/bpf_jit_harden": &fs.PathError{Op: "open", Path: "/proc/self/fd/5", Err: fs.ErrPermission}},
	}
	sys := fake{
		files: map[string]string{"module/apparmor/parameters/enabled": "Y", "fs/cgroup/cgroup.controllers": "cpu io"},
		// securityfs is not mounted: the witness exists but is empty.
		dirs: map[string][]string{"kernel/security": {}, "module": {"apparmor"}, "fs": {"cgroup"}, "fs/cgroup": {"cgroup.controllers"}},
	}
	b := (Collector{Proc: proc, Sys: sys, HostID: "h"}).Collect(context.Background())
	states := map[string]string{}
	for _, c := range b.Controls {
		states[c.Name] = string(c.State)
	}
	for name, want := range map[string]string{
		"sys/kernel/unprivileged_userns_clone": "not_applicable", // Debian-only patch absent
		"fs/selinux/enforce":                   "not_applicable", // selinuxfs absent: SELinux disabled
		"kernel/security/lsm":                  "unknown",        // securityfs not mounted
		"kernel/security/lockdown":             "unknown",
		"sys/net/core/bpf_jit_harden":          "unknown", // permission denied
		"sys/kernel/yama/ptrace_scope":         "observed",
	} {
		if states[name] != want {
			t.Errorf("%s: state %q, want %q", name, states[name], want)
		}
	}
	if b.Coverage.Unsupported != 2 || b.Coverage.Inconclusive != 3 || b.Coverage.Complete {
		t.Fatalf("unexpected coverage %+v", b.Coverage)
	}
	for _, d := range b.Diagnostics {
		if strings.Contains(d.Cause, "/proc/self/fd") {
			t.Fatalf("scanner-internal descriptor path leaked into cause: %q", d.Cause)
		}
	}
}

func TestOnlyExpectedAbsencesKeepKernelCoverageComplete(t *testing.T) {
	files := map[string]string{}
	for _, c := range controls {
		files[c.path] = "1"
	}
	delete(files, "fs/selinux/enforce")
	b := (Collector{Proc: fake{files: files}, Sys: fake{files: files, dirs: map[string][]string{"fs": {"cgroup"}}}, HostID: "h"}).Collect(context.Background())
	if !b.Coverage.Complete || b.Coverage.Unsupported != 1 {
		t.Fatalf("an established absence must not make coverage incomplete: %+v", b.Coverage)
	}
}
