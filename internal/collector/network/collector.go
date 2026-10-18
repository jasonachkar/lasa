package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
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
	return collector.Descriptor{ID: "network", Version: "1", Features: []string{"procfs socket tables"}, OptionalPrivileges: []string{"visibility into target network namespaces"}}
}
func (c Collector) Collect(ctx context.Context) (b domain.Batch) {
	b = collector.Begin("network", "TCP/UDP v4/v6 and UNIX tables for visible process network namespaces; interfaces only in scanner namespace")
	defer collector.Finish(&b)
	reps := map[string][]int{}
	for _, p := range c.Processes {
		if ns := p.Namespaces["net"]; ns != "" {
			reps[ns] = append(reps[ns], p.PID)
		}
	}
	names := make([]string, 0, len(reps))
	for ns := range reps {
		names = append(names, ns)
		sort.Ints(reps[ns])
	}
	sort.Strings(names)
	if len(names) > 128 {
		names = names[:128]
		b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("network", "network namespaces"))
		b.Coverage.Skipped++
	}
	owners := map[string]map[uint64][]string{}
	for _, p := range c.Processes {
		ns := p.Namespaces["net"]
		if owners[ns] == nil {
			owners[ns] = map[uint64][]string{}
		}
		for _, inode := range p.SocketInodes {
			owners[ns][inode] = append(owners[ns][inode], p.ID)
		}
	}
	for _, ns := range names {
		for _, table := range []string{"tcp", "tcp6", "udp", "udp6", "unix"} {
			if e := ctx.Err(); e != nil {
				b.Diagnostics = append(b.Diagnostics, diagnostics.New("network", "collect", ns, e))
				b.Coverage.Inconclusive++
				return
			}
			b.Coverage.Attempted++
			var raw []byte
			var e error
			target := ""
			for _, pid := range reps[ns] {
				target = strconv.Itoa(pid) + "/net/" + table
				raw, e = c.FS.Read(target)
				if e == nil {
					break
				}
			}
			if e != nil {
				d := diagnostics.New("network", "read", target, e)
				d.Code = "NETWORK_NAMESPACE_UNREADABLE"
				b.Diagnostics = append(b.Diagnostics, d)
				b.Coverage.Inconclusive++
				continue
			}
			var sockets []domain.Socket
			if table == "unix" {
				sockets, e = ParseUnix(raw, ns)
			} else {
				proto := table[:3]
				sockets, e = ParseTable(raw, proto, len(table) == 4, ns)
			}
			if e != nil {
				b.Diagnostics = append(b.Diagnostics, diagnostics.New("network", "parse", target, e))
				b.Coverage.Inconclusive++
				continue
			}
			b.Coverage.Successful++
			for i := range sockets {
				s := &sockets[i]
				s.Owners = owners[ns][s.Inode]
				sort.Strings(s.Owners)
				b.Observations = append(b.Observations, domain.Fact(s.ID, "socket.endpoint", fmt.Sprintf("%s:%d", s.Address, s.Port), target, "network", domain.Observed, time.Now().UTC()))
			}
			if len(b.Sockets)+len(sockets) > 65536 {
				b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("network", "total sockets"))
				b.Coverage.Inconclusive++
				return
			}
			b.Sockets = append(b.Sockets, sockets...)
		}
	}
	ifaces, e := net.Interfaces()
	b.Coverage.Attempted++
	if e != nil {
		b.Diagnostics = append(b.Diagnostics, diagnostics.New("network", "interfaces", "scanner network namespace", e))
		b.Coverage.Inconclusive++
	} else {
		b.Coverage.Successful++
		for _, i := range ifaces {
			item := domain.Interface{ID: domain.Hash(c.Host.NetworkNamespace, i.Name), Name: i.Name, Index: i.Index, Flags: i.Flags.String(), Namespace: c.Host.NetworkNamespace}
			a, e := i.Addrs()
			if e != nil {
				b.Diagnostics = append(b.Diagnostics, diagnostics.New("network", "addresses", i.Name, e))
				b.Coverage.Inconclusive++
			}
			for _, v := range a {
				item.Addresses = append(item.Addresses, v.String())
			}
			sort.Strings(item.Addresses)
			b.Interfaces = append(b.Interfaces, item)
		}
	}
	for _, name := range []string{"net/route", "net/ipv6_route"} {
		b.Coverage.Attempted++
		raw, e := c.FS.Read(strconv.Itoa(os.Getpid()) + "/" + name)
		if e != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("network", "route_table", name, e))
			b.Coverage.Inconclusive++
		} else {
			b.Coverage.Successful++
			b.Observations = append(b.Observations, domain.Fact(c.Host.ID, "topology."+name, string(raw), "procfs "+name, "network", domain.Observed, time.Now().UTC()))
		}
	}
	return
}
