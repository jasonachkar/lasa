package identity

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

type Collector struct {
	FS        linux.Reader
	Processes []domain.Process
	Host      domain.Host
}

func (c Collector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "identity", Version: "1", Features: []string{"procfs uid/gid mappings and mountinfo"}}
}
func (c Collector) Collect(ctx context.Context) (b domain.Batch) {
	b = collector.Begin("identity", "visible mount namespaces and user mappings; initial user namespace inferred only from full identity mapping")
	defer collector.Finish(&b)
	reps := map[string]int{}
	for _, p := range c.Processes {
		if n := p.Namespaces["mnt"]; n != "" {
			pid, ok := reps[n]
			if !ok || p.PID < pid {
				reps[n] = p.PID
			}
		}
	}
	self := strconv.Itoa(os.Getpid())
	if ns, e := c.FS.Readlink(self + "/ns/mnt"); e == nil {
		reps[ns] = os.Getpid()
	}
	names := make([]string, 0, len(reps))
	for ns := range reps {
		names = append(names, ns)
	}
	sort.Strings(names)
	if len(names) > 128 {
		names = names[:128]
		b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("identity", "mount namespaces"))
		b.Coverage.Skipped++
	}
	for _, ns := range names {
		b.Coverage.Attempted++
		if ctx.Err() != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("identity", "collect", ns, ctx.Err()))
			b.Coverage.Inconclusive++
			break
		}
		path := strconv.Itoa(reps[ns]) + "/mountinfo"
		raw, e := c.FS.Read(path)
		if e != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("identity", "read", linux.Source(c.FS, path), e))
			b.Coverage.Inconclusive++
			continue
		}
		mounts, e := ParseMounts(raw, ns)
		if e != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("identity", "parse", linux.Source(c.FS, path), e))
			b.Coverage.Inconclusive++
			continue
		}
		b.Coverage.Successful++
		if len(b.Mounts)+len(mounts) > 32768 {
			b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("identity", "total mounts"))
			b.Coverage.Inconclusive++
			return
		}
		b.Mounts = append(b.Mounts, mounts...)
		for _, m := range mounts {
			b.Observations = append(b.Observations, domain.Fact(m.ID, "mount.options", strings.Join(m.Options, ","), linux.Source(c.FS, path), "identity", domain.Observed, time.Now().UTC()))
		}
	}
	return
}
