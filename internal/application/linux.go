package application

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/jasonachkar/lasa/internal/collector"
	sensor "github.com/jasonachkar/lasa/internal/collector/ebpf"
	"github.com/jasonachkar/lasa/internal/collector/filesystem"
	"github.com/jasonachkar/lasa/internal/collector/identity"
	"github.com/jasonachkar/lasa/internal/collector/kernel"
	"github.com/jasonachkar/lasa/internal/collector/network"
	"github.com/jasonachkar/lasa/internal/collector/process"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"github.com/jasonachkar/lasa/internal/rules"
)

func Linux(c config.Config, pack []rules.Rule) (Engine, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return Engine{}, fmt.Errorf("HOST_UNSUPPORTED: LASA requires Linux AMD64 or ARM64")
	}
	if e := c.Validate(); e != nil {
		return Engine{}, e
	}
	if c.Profile == "deep" && os.Geteuid() != 0 {
		return Engine{}, fmt.Errorf("PERMISSION_DENIED: deep profile requires an explicitly authorized effective UID 0; scanner does not elevate")
	}
	proc := linux.FS{Root: c.Proc, Limit: c.MaxRead}
	sys := linux.FS{Root: "/sys", Limit: c.MaxRead}
	host, ds := hostInfo(proc, c.Profile)
	e := Engine{Host: host, Rules: pack, Diagnostics: ds}
	e.Stages = []Stage{func(*domain.Snapshot) []collector.Collector {
		sources := []collector.Collector{process.Collector{FS: proc, Config: c, Host: host}, kernel.Collector{Proc: proc, Sys: sys, HostID: host.ID}}
		if c.Profile == "sensor" {
			sources = append(sources, sensor.Collector{Duration: c.SensorDuration, MaxEvents: 4096, BootID: host.BootID})
		}
		return sources
	}, func(s *domain.Snapshot) []collector.Collector {
		return []collector.Collector{network.Collector{FS: proc, Processes: s.Processes, Host: host}, identity.Collector{FS: proc, Processes: s.Processes, Host: host}}
	}, func(s *domain.Snapshot) []collector.Collector {

		return []collector.Collector{filesystem.Collector{Config: c, HostID: host.ID}}
	}}
	return e, nil
}
func hostInfo(proc linux.Reader, profile string) (domain.Host, []domain.Diagnostic) {
	h := domain.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Scope: "Visible process and network namespaces; scoped file metadata. Host boundary and upstream reachability are not assumed."}
	if profile == "container" {
		h.Scope = "Container-view scan: only namespaces and mounted metadata visible to this process; no claim of full host visibility."
	}
	var ds []domain.Diagnostic
	read := func(path string) string {
		b, e := proc.Read(path)
		if e != nil {
			ds = append(ds, diagnostics.New("host", "read_metadata", path, e))
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	h.BootID = read("sys/kernel/random/boot_id")
	h.Kernel = read("sys/kernel/osrelease")
	system := linux.FS{Root: "/", Limit: 4096}
	machine, e := system.Read("etc/machine-id")
	if e != nil {
		machine, e = system.Read("var/lib/dbus/machine-id")
	}
	if e != nil || len(strings.TrimSpace(string(machine))) < 16 {
		ds = append(ds, diagnostics.New("host", "read_identity", "machine-id", fmt.Errorf("stable machine identity unavailable; boot-scoped fallback used")))
		machine = []byte(h.BootID)
	}
	h.ID = domain.Hash("lasa.host/v1", strings.TrimSpace(string(machine)))
	for _, path := range []string{"usr/lib/os-release", "etc/os-release"} {
		b, e := system.Read(path)
		if e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if k, v, ok := strings.Cut(line, "="); ok && k == "PRETTY_NAME" {
					h.Distribution = strings.Trim(v, "\"")
				}
			}
			break
		}
	}
	for _, ns := range []struct {
		name string
		dest *string
	}{{"pid", &h.PIDNamespace}, {"user", &h.UserNamespace}, {"net", &h.NetworkNamespace}} {
		s, e := proc.Readlink(strconv.Itoa(os.Getpid()) + "/ns/" + ns.name)
		if e != nil {
			ds = append(ds, diagnostics.New("host", "read_namespace", ns.name, e))
		} else {
			*ns.dest = s
		}
	}
	return h, ds
}
