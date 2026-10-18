package process

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jasonachkar/lasa/internal/collector"
	ct "github.com/jasonachkar/lasa/internal/collector/container"
	"github.com/jasonachkar/lasa/internal/collector/identity"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

type Collector struct {
	FS     linux.Reader
	Config config.Config
	Host   domain.Host
}

func (c Collector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "process", Version: "1", Features: []string{"procfs", "openat2"}, OptionalPrivileges: []string{"host procfs visibility; ptrace access policy for other users' descriptor metadata"}}
}
func (c Collector) Collect(ctx context.Context) (b domain.Batch) {
	b = collector.Begin("process", "bounded visible procfs PIDs; no arguments or environments")
	defer collector.Finish(&b)
	names, cut, e := c.FS.Names(".", c.Config.MaxProcesses*2+128)
	if e != nil {
		b.Diagnostics = append(b.Diagnostics, diagnostics.New("process", "enumerate", c.Config.Proc, e))
		b.Coverage.Inconclusive++
		return b
	}
	var pids []int
	for _, n := range names {
		if p, e := strconv.Atoi(n); e == nil && p > 0 {
			pids = append(pids, p)
		}
	}
	sort.Ints(pids)
	if len(pids) > c.Config.MaxProcesses {
		pids = pids[:c.Config.MaxProcesses]
		cut = true
	}
	if cut {
		b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("process", "procfs PIDs"))
		b.Coverage.Skipped++
	}
	jobs := make(chan int)
	results := make(chan domain.Batch, c.Config.Workers)
	var wg sync.WaitGroup
	for i := 0; i < c.Config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range jobs {
				if ctx.Err() != nil {
					return
				}
				results <- c.one(ctx, pid)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, pid := range pids {
			select {
			case jobs <- pid:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	for r := range results {
		b.Coverage.Attempted++
		b.Coverage.Successful += len(r.Processes)
		b.Coverage.Inconclusive += r.Coverage.Inconclusive
		b.Processes = append(b.Processes, r.Processes...)
		b.Observations = append(b.Observations, r.Observations...)
		b.Diagnostics = append(b.Diagnostics, r.Diagnostics...)
		b.Services = append(b.Services, r.Services...)
		b.Containers = append(b.Containers, r.Containers...)
	}
	if ctx.Err() != nil {
		b.Diagnostics = append(b.Diagnostics, diagnostics.New("process", "collect", "procfs", ctx.Err()))
		b.Coverage.Inconclusive++
	}
	return b
}
func (c Collector) one(ctx context.Context, pid int) domain.Batch {
	var b domain.Batch
	prefix := strconv.Itoa(pid) + "/"
	at := time.Now().UTC()
	fail := func(op, p string, e error) {
		d := diagnostics.New("process", op, linux.Source(c.FS, prefix+p), e)
		if os.IsNotExist(e) {
			d.Code = "PROCESS_VANISHED"
			d.Remediation = "Expected for short-lived processes; rerun to observe current state."
		}
		b.Diagnostics = append(b.Diagnostics, d)
		b.Coverage.Inconclusive++
	}
	read := func(p string) ([]byte, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		return c.FS.Read(prefix + p)
	}
	raw, e := read("stat")
	if e != nil {
		fail("read", "stat", e)
		return b
	}
	actual, ppid, start, e := ParseStat(raw)
	if e != nil || actual != pid {
		if e == nil {
			e = fmt.Errorf("PID changed while reading")
		}
		fail("parse", "stat", e)
		return b
	}
	raw, e = read("status")
	if e != nil {
		fail("read", "status", e)
		return b
	}
	p, e := ParseStatus(raw)
	if e != nil {
		fail("parse", "status", e)
		return b
	}
	p.PID = pid
	p.PPID = ppid
	p.StartTime = start
	for _, ns := range []string{"user", "pid", "net", "mnt", "ipc", "uts", "cgroup"} {
		s, e := c.FS.Readlink(prefix + "ns/" + ns)
		if e != nil {
			fail("readlink", "ns/"+ns, e)
		} else {
			p.Namespaces[ns] = s
		}
	}
	p.ID = domain.Hash(c.Host.BootID, p.Namespaces["pid"], strconv.Itoa(pid), strconv.FormatUint(start, 10))
	for _, v := range []struct {
		path string
		dest *string
	}{{"uid_map", &p.Identity.UIDMap}, {"gid_map", &p.Identity.GIDMap}} {
		r, e := read(v.path)
		if e != nil {
			fail("read", v.path, e)
		} else {
			*v.dest = strings.TrimSpace(string(r))
		}
	}
	var exe string
	if accessor, ok := c.FS.(interface {
		Executable(string) (string, uint64, uint64, error)
	}); ok {
		exe, p.ExecutableInode, p.ExecutableDevice, e = accessor.Executable(strconv.Itoa(pid))
	} else {
		exe, e = c.FS.Readlink(prefix + "exe")
	}
	if e != nil {
		fail("executable_metadata", "exe", e)
	} else {
		p.Executable = exe
	}

	raw, e = read("cgroup")
	cgroupKnown := e == nil
	if e != nil {
		fail("read", "cgroup", e)
	} else {
		p.Cgroups = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	p.Service = ct.Service(p.Cgroups)
	hint := ct.Hint(p.Cgroups)
	p.ContainerHint = hint != ""
	var cgroupRedacted bool
	p.Cgroups, cgroupRedacted = ct.Redact(p.Cgroups)
	resource := p.Executable
	if resource == "" {
		resource = p.ID
	}
	if p.Service != "" {
		resource = p.Service
	}
	p.StableID = domain.Hash(c.Host.ID, resource, strconv.FormatUint(uint64(p.Identity.UID[1]), 10), strings.Join(p.Cgroups, ";"))
	if p.Service != "" {
		b.Services = append(b.Services, domain.Service{ID: domain.Hash(c.Host.ID, p.Service), Name: p.Service, Process: p.ID, Source: prefix + "cgroup"})
	}
	if hint != "" {
		b.Containers = append(b.Containers, domain.Container{ID: domain.Hash(c.Host.ID, strings.Join(p.Cgroups, ";")), Process: p.ID, Hint: hint, Confidence: "low"})
	}
	names, cut, e := c.FS.Names(prefix+"fd", c.Config.MaxFDs)
	p.FDComplete = e == nil && !cut
	if e != nil {
		fail("enumerate", "fd", e)
	}
	if cut {
		b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("process", prefix+"fd"))
		b.Coverage.Inconclusive++
	}
	for _, fd := range names {
		if ctx.Err() != nil {
			fail("readlink", "fd", ctx.Err())
			break
		}
		target, e := c.FS.Readlink(prefix + "fd/" + fd)
		if e != nil {
			p.FDComplete = false
			fail("readlink", "fd/"+fd, e)
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			n, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if e != nil {
				fail("parse", "fd/"+fd, e)
				continue
			}
			p.SocketInodes = append(p.SocketInodes, n)
		}
	}
	sort.Slice(p.SocketInodes, func(i, j int) bool { return p.SocketInodes[i] < p.SocketInodes[j] })
	raw, e = read("stat")
	if e != nil {
		fail("verify_identity", "stat", e)
		return b
	}
	_, _, end, e := ParseStat(raw)
	if e != nil || end != start {
		if e == nil {
			e = fmt.Errorf("PID reuse detected: start time changed")
		}
		fail("verify_identity", "stat", e)
		return b
	}
	fact := func(key, value, source string, state domain.State) {
		b.Observations = append(b.Observations, domain.Fact(p.ID, key, value, func() string {
			if strings.Contains(source, " + ") {
				return "process derivation: " + source
			}
			return linux.Source(c.FS, prefix+source)
		}(), "process", state, at))
	}
	fact("process.identity", p.ID, "stat", domain.Observed)
	fact("process.executable", p.Executable, "exe", state(p.Executable != ""))
	fact("process.executable_inode", fmt.Sprintf("%d:%d", p.ExecutableDevice, p.ExecutableInode), "exe", state(p.ExecutableInode != 0))
	fact("isolation.seccomp", strconv.Itoa(p.Seccomp), "status", state(p.Seccomp >= 0))
	fact("isolation.no_new_privs", strconv.Itoa(p.NoNewPrivs), "status", state(p.NoNewPrivs >= 0))
	fact("identity.euid", strconv.FormatUint(uint64(p.Identity.UID[1]), 10), "status", domain.Observed)
	fact("identity.uid_map", p.Identity.UIDMap, "uid_map", state(p.Identity.UIDMap != ""))
	fact("privilege.host_root", strconv.FormatBool(p.Identity.UID[1] == 0 && identity.InitialMapping(p.Identity.UIDMap) && p.Namespaces["user"] == "user:[4026531837]"), "uid_map + status", state(p.Identity.UIDMap != "" && p.Namespaces["user"] != ""))
	cap, ok := p.Capabilities["CapEff"]
	danger := cap&((1<<21)|(1<<19)|(1<<1)|(1<<2)|(1<<16)) != 0
	fact("capability.dangerous", strconv.FormatBool(danger && identity.InitialMapping(p.Identity.UIDMap) && p.Namespaces["user"] == "user:[4026531837]"), "status + uid_map", state(ok && p.Identity.UIDMap != "" && p.Namespaces["user"] != ""))
	fact("capability.mask", fmt.Sprintf("%x", cap), "status", state(ok))
	fact("isolation.weak", strconv.FormatBool(p.Seccomp == 0 && p.NoNewPrivs == 0), "status", state(p.Seccomp >= 0 && p.NoNewPrivs >= 0))
	fact("container.hint", strconv.FormatBool(p.ContainerHint), "cgroup", state(cgroupKnown))
	fact("cgroup.context", strings.Join(p.Cgroups, ";"), "cgroup", state(cgroupKnown))
	if cgroupRedacted {
		b.Observations[len(b.Observations)-1].Redacted = true
	}
	fact("descriptor.complete", strconv.FormatBool(p.FDComplete), "fd", domain.Observed)
	for ns, val := range p.Namespaces {
		fact("namespace."+ns, val, "ns/"+ns, domain.Observed)
	}
	derivedSources := map[string][]string{"privilege.host_root": {"identity.euid", "identity.uid_map", "namespace.user"}, "capability.dangerous": {"capability.mask", "identity.uid_map", "namespace.user"}, "isolation.weak": {"isolation.seccomp", "isolation.no_new_privs"}, "container.hint": {"cgroup.context"}}
	ids := map[string]string{}
	for _, o := range b.Observations {
		ids[o.Key] = o.ID
	}
	for i := range b.Observations {
		if keys, ok := derivedSources[b.Observations[i].Key]; ok {
			b.Observations[i].Derived = true
			for _, key := range keys {
				if id := ids[key]; id != "" {
					b.Observations[i].Evidence = append(b.Observations[i].Evidence, id)
				}
			}
		}
	}
	b.Processes = append(b.Processes, p)
	return b
}
func state(ok bool) domain.State {
	if ok {
		return domain.Observed
	}
	return domain.Unknown
}
