package kernel

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

type Collector struct {
	Proc   linux.Reader
	Sys    linux.Reader
	HostID string
}

// control is an allowlisted kernel setting. A missing control is only treated
// as absent from this kernel when its witness directory is visible and
// populated: then the kernel interface was enumerable and simply does not
// provide the control (for example SELinux on an AppArmor host). Without that
// witness, for example when securityfs is not mounted, absence stays unknown.
type control struct {
	path    string
	sys     bool
	witness string
	feature string
}

var controls = []control{
	{"sys/kernel/yama/ptrace_scope", false, "sys/kernel", "Yama LSM"},
	{"sys/kernel/kptr_restrict", false, "sys/kernel", "kptr_restrict"},
	{"sys/kernel/dmesg_restrict", false, "sys/kernel", "dmesg_restrict"},
	{"sys/kernel/unprivileged_bpf_disabled", false, "sys/kernel", "BPF syscall"},
	{"sys/kernel/unprivileged_userns_clone", false, "sys/kernel", "Debian unprivileged_userns_clone patch"},
	{"sys/user/max_user_namespaces", false, "sys/user", "user namespaces"},
	{"sys/net/core/bpf_jit_harden", false, "sys/net/core", "BPF JIT"},
	{"kernel/security/lsm", true, "kernel/security", "LSM list"},
	{"kernel/security/lockdown", true, "kernel/security", "lockdown LSM"},
	{"module/apparmor/parameters/enabled", true, "module", "AppArmor"},
	{"fs/selinux/enforce", true, "fs", "SELinux (selinuxfs is only mounted when SELinux is enabled)"},
	{"fs/cgroup/cgroup.controllers", true, "fs/cgroup", "unified cgroup v2 hierarchy"},
}

func (c Collector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "kernel", Version: "1", Features: []string{"sysctl metadata", "sysfs LSM metadata"}}
}
func (c Collector) Collect(ctx context.Context) (b domain.Batch) {
	b = collector.Begin("kernel", "allowlisted kernel controls; controls this kernel does not provide are not applicable; inaccessible controls are unknown, never secure")
	defer collector.Finish(&b)
	for _, x := range controls {
		if ctx.Err() != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("kernel", "collect", x.path, ctx.Err()))
			b.Coverage.Inconclusive++
			break
		}
		b.Coverage.Attempted++
		reader := c.Proc
		if x.sys {
			reader = c.Sys
		}
		source := linux.Source(reader, x.path)
		raw, e := reader.Read(x.path)
		state := domain.Observed
		value := strings.TrimSpace(string(raw))
		switch {
		case e == nil:
			b.Coverage.Successful++
		case errors.Is(e, os.ErrNotExist) && populated(reader, x.witness):
			state = domain.NotApplicable
			value = ""
			b.Diagnostics = append(b.Diagnostics, diagnostics.Expected(diagnostics.CodeNotSupported, "kernel", "read_control", source,
				"this kernel does not provide "+x.feature,
				"The control does not exist here, so there is no setting to evaluate.",
				"No action is needed; this is a property of the running kernel."))
			b.Coverage.Unsupported++
		default:
			state = domain.Unknown
			d := diagnostics.New("kernel", "read_control", source, e)
			d.Cause = plainCause(e)
			b.Diagnostics = append(b.Diagnostics, d)
			b.Coverage.Inconclusive++
		}
		id := domain.Hash(c.HostID, x.path)
		b.Controls = append(b.Controls, domain.KernelControl{ID: id, Name: x.path, Value: value, State: state, Source: source})
		b.Observations = append(b.Observations, domain.Fact(id, "control.value", value, source, "kernel", state, time.Now().UTC()))
	}
	return
}

// populated reports whether a witness directory is visible and non-empty.
func populated(r linux.Reader, dir string) bool {
	names, _, e := r.Names(dir, 1)
	return e == nil && len(names) > 0
}

// plainCause removes scanner-internal descriptor paths (such as
// /proc/self/fd/N used to pin a file) from an error, keeping the errno text.
func plainCause(e error) string {
	var pathError *os.PathError
	if errors.As(e, &pathError) {
		return pathError.Err.Error()
	}
	return e.Error()
}
