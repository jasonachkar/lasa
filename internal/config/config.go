package config

import (
	"fmt"
	"path/filepath"
	"time"
)

type Config struct {
	Profile        string
	SensorDuration time.Duration
	Timeout        time.Duration
	Workers        int
	MaxProcesses   int
	MaxFDs         int
	MaxFiles       int
	MaxRead        int64
	Roots          []string
	Proc           string
}

func Default() Config {
	return Config{Profile: "standard", SensorDuration: 3 * time.Second, Timeout: 30 * time.Second, Workers: 4, MaxProcesses: 4096, MaxFDs: 512, MaxFiles: 4096, MaxRead: 1 << 20, Proc: "/proc", Roots: []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/etc/systemd/system", "/usr/lib/systemd/system", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/root/.ssh", "/run/docker.sock", "/run/containerd/containerd.sock"}}
}
func (c Config) Validate() error {
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
