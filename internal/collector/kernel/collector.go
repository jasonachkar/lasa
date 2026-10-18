package kernel

import (
	"context"
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

func (c Collector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "kernel", Version: "1", Features: []string{"sysctl metadata", "sysfs LSM metadata"}}
}
func (c Collector) Collect(ctx context.Context) (b domain.Batch) {
	b = collector.Begin("kernel", "allowlisted kernel controls; missing paths mean unknown, never secure")
	defer collector.Finish(&b)
	for _, x := range []struct {
		path string
		sys  bool
	}{{"sys/kernel/yama/ptrace_scope", false}, {"sys/kernel/kptr_restrict", false}, {"sys/kernel/dmesg_restrict", false}, {"sys/kernel/unprivileged_bpf_disabled", false}, {"sys/kernel/unprivileged_userns_clone", false}, {"sys/user/max_user_namespaces", false}, {"sys/net/core/bpf_jit_harden", false}, {"kernel/security/lsm", true}, {"kernel/security/lockdown", true}, {"module/apparmor/parameters/enabled", true}, {"fs/selinux/enforce", true}, {"fs/cgroup/cgroup.controllers", true}} {
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
		raw, e := reader.Read(x.path)
		state := domain.Observed
		value := strings.TrimSpace(string(raw))
		if e != nil {
			state = domain.Unknown
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("kernel", "read_control", x.path, e))
			b.Coverage.Inconclusive++
		} else {
			b.Coverage.Successful++
		}
		id := domain.Hash(c.HostID, x.path)
		b.Controls = append(b.Controls, domain.KernelControl{ID: id, Name: x.path, Value: value, State: state, Source: x.path})
		b.Observations = append(b.Observations, domain.Fact(id, "control.value", value, x.path, "kernel", state, time.Now().UTC()))
	}
	return
}
