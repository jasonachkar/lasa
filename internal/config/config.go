package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

type Config struct {
	Inspect                  []string
	SSHContexts              []string
	NetworkSource            string
	NetworkDestination       string
	NetworkInterface         string
	AdvisoryFile             string
	ContainerSocket          string
	MaxInspectionItems       int
	InspectionCommandTimeout time.Duration
	AdvisoryMaxAge           time.Duration
	Profile                  string
	SensorDuration           time.Duration
	Timeout                  time.Duration
	Workers                  int
	MaxProcesses             int
	MaxFDs                   int
	MaxFiles                 int
	MaxRead                  int64
	Roots                    []string
	Proc                     string
}

func Default() Config {
	return Config{MaxInspectionItems: 256, InspectionCommandTimeout: 5 * time.Second, AdvisoryMaxAge: 7 * 24 * time.Hour, ContainerSocket: "/run/docker.sock", Profile: "standard", SensorDuration: 3 * time.Second, Timeout: 30 * time.Second, Workers: 4, MaxProcesses: 4096, MaxFDs: 512, MaxFiles: 4096, MaxRead: 1 << 20, Proc: "/proc", Roots: []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/etc/systemd/system", "/usr/lib/systemd/system", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/root/.ssh", "/run/docker.sock", "/run/containerd/containerd.sock"}}
}
func (c Config) Validate() error {
	if c.MaxInspectionItems != 0 && (c.MaxInspectionItems < 1 || c.MaxInspectionItems > 4096) {
		return fmt.Errorf("max-inspection-items must be 1..4096")
	}
	if len(c.Inspect) > 0 && (c.InspectionCommandTimeout < time.Millisecond || c.InspectionCommandTimeout > time.Minute) {
		return fmt.Errorf("inspection command timeout must be 1ms..1m")
	}
	if c.AdvisoryMaxAge < 0 || c.AdvisoryMaxAge > 365*24*time.Hour {
		return fmt.Errorf("advisory-max-age must be 0..8760h")
	}
	seen := map[string]bool{}
	for _, name := range c.Inspect {
		if !slices.Contains(InspectionModules, name) && name != "all" {
			return fmt.Errorf("unknown inspection %q; choose %s", name, strings.Join(InspectionModules, ","))
		}
		if seen[name] {
			return fmt.Errorf("duplicate inspection %q", name)
		}
		seen[name] = true
	}
	if seen["all"] && len(c.Inspect) > 1 {
		return fmt.Errorf("all cannot be combined with individual inspections")
	}
	if len(c.Inspect) > 0 && c.MaxInspectionItems == 0 {
		return fmt.Errorf("max-inspection-items must be 1..4096")
	}
	for _, context := range c.SSHContexts {
		if e := ValidateSSHContext(context); e != nil {
			return e
		}
	}
	for _, address := range []string{c.NetworkSource, c.NetworkDestination} {
		if address != "" {
			ip, e := netip.ParseAddr(address)
			if e != nil || ip.Zone() != "" {
				return fmt.Errorf("network source/destination must be an IP address without a zone")
			}
		}
	}
	if len(c.NetworkInterface) > 15 || strings.ContainsAny(c.NetworkInterface, " /\\\r\n\x00") {
		return fmt.Errorf("invalid network interface name")
	}
	if len(c.SSHContexts) > 32 {
		return fmt.Errorf("at most 32 SSH contexts are supported")
	}
	if len(c.ContainerSocket) > 0 && (!filepath.IsAbs(c.ContainerSocket) || filepath.Clean(c.ContainerSocket) != c.ContainerSocket) {
		return fmt.Errorf("container socket must be an absolute normalized path")
	}
	switch c.Profile {
	case "standard", "deep", "container", "sensor":
	default:
		return fmt.Errorf("unknown profile %q; use standard, deep, container or sensor", c.Profile)
	}
	if c.SensorDuration < time.Millisecond || c.SensorDuration > 10*time.Minute {
		return fmt.Errorf("sensor duration must be 1ms..10m")
	}
	if c.Timeout < time.Millisecond || c.Timeout > 24*time.Hour {
		return fmt.Errorf("timeout must be between 1ms and 24h")
	}
	if c.Workers < 1 || c.Workers > 32 {
		return fmt.Errorf("workers must be 1..32")
	}
	if c.MaxProcesses < 1 || c.MaxProcesses > 65536 || c.MaxFDs < 1 || c.MaxFDs > 65536 || c.MaxFiles < 1 || c.MaxFiles > 100000 {
		return fmt.Errorf("process/FD/file budget outside supported limits")
	}
	if c.MaxRead < 1024 || c.MaxRead > 16<<20 {
		return fmt.Errorf("metadata read limit must be 1KiB..16MiB")
	}
	if !filepath.IsAbs(c.Proc) {
		return fmt.Errorf("proc root must be absolute")
	}
	if len(c.Roots) > 128 {
		return fmt.Errorf("at most 128 file roots are supported")
	}
	for _, p := range c.Roots {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return fmt.Errorf("file root %q must be absolute, normalized and narrower than /", p)
		}
	}
	return nil
}

var InspectionModules = []string{"systemd", "ssh", "sudo", "permissions", "firewall", "containers", "packages", "scheduler"}

func (c Config) Modules() []string {
	if slices.Contains(c.Inspect, "all") {
		out := append([]string(nil), InspectionModules...)
		sort.Strings(out)
		return out
	}
	out := append([]string(nil), c.Inspect...)
	sort.Strings(out)
	return out
}
func (c Config) ScopeID() string {
	roots := append([]string(nil), c.Roots...)
	sort.Strings(roots)
	contexts := append([]string(nil), c.SSHContexts...)
	sort.Strings(contexts)
	raw, _ := json.Marshal([]any{c.Profile, roots, c.Modules(), contexts, c.NetworkSource, c.NetworkDestination, c.NetworkInterface, c.ContainerSocket, c.AdvisoryFile})
	return domain.Hash("lasa.scope/v2", string(raw))
}

func ValidateSSHContext(s string) error {
	if len(s) > 2048 {
		return fmt.Errorf("SSH context exceeds 2048 bytes")
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || v == "" || seen[k] || !slices.Contains([]string{"user", "host", "addr", "laddr", "lport", "rdomain"}, k) || strings.ContainsAny(v, "\r\n\x00 \t") {
			return fmt.Errorf("invalid SSH context field; use user,host,addr,laddr,lport")
		}
		seen[k] = true
		if k == "addr" || k == "laddr" {
			ip, e := netip.ParseAddr(v)
			if e != nil || ip.Zone() != "" {
				return fmt.Errorf("SSH %s must be an IP address without a zone", k)
			}
		}
		if k == "lport" {
			p, e := strconv.Atoi(v)
			if e != nil || p < 1 || p > 65535 {
				return fmt.Errorf("SSH lport must be 1..65535")
			}
		}
	}
	for _, key := range []string{"user", "host", "addr", "laddr", "lport"} {
		if !seen[key] {
			return fmt.Errorf("SSH context requires user,host,addr,laddr,lport")
		}
	}
	return nil
}
