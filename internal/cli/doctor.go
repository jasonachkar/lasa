package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"github.com/jasonachkar/lasa/internal/report"
	"github.com/spf13/cobra"
)

type DoctorCheck struct {
	Name       string             `json:"name"`
	Required   bool               `json:"required"`
	State      domain.State       `json:"state"`
	Detail     string             `json:"detail"`
	Diagnostic *domain.Diagnostic `json:"diagnostic,omitempty"`
}

func doctorCommand() *cobra.Command {
	var format string
	returnCommand := &cobra.Command{Use: "doctor", Short: "Inspect static scan visibility and optional sensor prerequisites", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if format != "json" && format != "terminal" {
			return fmt.Errorf("doctor format must be terminal or json")
		}
		checks := []DoctorCheck{{Name: "platform", Required: true, State: domain.Observed, Detail: runtime.GOOS + "/" + runtime.GOARCH}, {Name: "privilege", Required: false, State: domain.Observed, Detail: fmt.Sprintf("effective UID %d; no automatic elevation", os.Geteuid())}}
		if runtime.GOOS != "linux" {
			checks[0].State = domain.NotApplicable
		}
		proc := linux.FS{Root: "/proc", Limit: 1 << 20}
		pid := strconv.Itoa(os.Getpid())
		for _, x := range []struct {
			name, path string
			required   bool
		}{{"procfs", pid + "/stat", true}, {"process_security", pid + "/status", true}, {"socket_visibility", pid + "/net/tcp", true}, {"mount_visibility", pid + "/mountinfo", false}, {"boot_identity", "sys/kernel/random/boot_id", true}} {
			item := DoctorCheck{Name: x.name, Required: x.required, State: domain.Observed, Detail: "readable: /proc/" + x.path}
			_, e := proc.Read(x.path)
			if e != nil {
				item.State = domain.Unknown
				d := diagnostics.New("doctor", "read", x.path, e)
				item.Diagnostic = &d
				item.Detail = d.Cause
			}
			checks = append(checks, item)
		}
		for _, x := range []struct{ name, path, code string }{{"ebpf_btf", "kernel/btf/vmlinux", "BTF_UNAVAILABLE"}, {"ebpf_tracepoints", "kernel/tracing/events/sched/sched_process_exec/format", "TRACEPOINT_UNAVAILABLE"}} {
			sys := linux.FS{Root: "/sys", Limit: 4096}
			h, e := linux.Open(sys.Root, x.path, 0)
			item := DoctorCheck{Name: x.name, State: domain.Observed, Detail: "optional sensor metadata visible"}
			if e != nil {
				item.State = domain.Unknown
				d := diagnostics.New("doctor", "open", sys.Root+"/"+x.path, e)
				d.Code = x.code
				d.Remediation = "Optional eBPF needs host BTF and tracefs visibility plus authorized BPF/perf permissions. Static scans remain available."
				item.Diagnostic = &d
				item.Detail = d.Cause
			} else {
				_ = h.Close()
			}
			checks = append(checks, item)
		}
		requiredOK := true
		for _, check := range checks {
			if check.Required && check.State != domain.Observed {
				requiredOK = false
			}
		}
		if format == "json" {
			raw, e := json.MarshalIndent(map[string]any{"schema": "lasa.doctor/v1", "at": time.Now().UTC(), "static_prerequisites_available": requiredOK, "checks": checks}, "", "  ")
			if e != nil {
				return e
			}
			if e = write(c, raw, ""); e != nil {
				return e
			}
		} else {
			var b strings.Builder
			fmt.Fprintf(&b, "LASA doctor: static prerequisites available=%t\n", requiredOK)
			for _, check := range checks {
				fmt.Fprintf(&b, "%s required=%t state=%s: %s\n", check.Name, check.Required, check.State, report.Safe(check.Detail))
				if check.Diagnostic != nil {
					fmt.Fprintf(&b, "  %s\n", report.Safe(check.Diagnostic.Error()))
				}
			}
			b.WriteString("BTF visibility alone does not prove BPF load, attachment, or event delivery. Container views and hidepid may conceal other processes.\n")
			if e := write(c, []byte(b.String()), ""); e != nil {
				return e
			}
		}
		if !requiredOK {
			return &ExitError{2, nil}
		}
		return nil
	}}
	returnCommand.Flags().StringVar(&format, "format", "terminal", "terminal or json")
	return returnCommand
}
