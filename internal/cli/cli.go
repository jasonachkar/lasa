// Package cli exposes stable local scanner commands. Machine output goes only to stdout.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/application"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
	"github.com/jasonachkar/lasa/internal/rules"
	"github.com/jasonachkar/lasa/internal/storage"
	"github.com/jasonachkar/lasa/rules/builtin"
	"github.com/spf13/cobra"
)

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}
func (e *ExitError) Unwrap() error { return e.Err }
func ExitCode(e error) int {
	if e == nil {
		return 0
	}
	var x *ExitError
	if errors.As(e, &x) {
		return x.Code
	}
	if errors.Is(e, context.Canceled) {
		return 130
	}
	return 2
}

// cliHints are code-specific next steps for command errors. Command errors
// do not concern collected evidence, so they carry no evidence impact.
var cliHints = map[string]string{
	"CONFIG_INVALID":      "Run lasa COMMAND --help for supported values.",
	"OUTPUT_WRITE_FAILED": "Write to an existing private directory you own (or that root owns), or omit --output to write to stdout.",
	"REPORT_READ_FAILED":  "Pass the path of a regular JSON file written by lasa scan --format json.",
	"REPORT_INVALID":      "Pass an unmodified JSON report written by a compatible lasa scan --format json.",
	"FINDING_NOT_FOUND":   "List finding IDs with lasa report --input REPORT; a unique prefix of at least 6 characters is accepted.",
	"FINDING_AMBIGUOUS":   "Use one of the listed IDs or a longer prefix.",
	"PERMISSION_DENIED":   "Run the deep profile as root (for example with sudo) only when a host-wide scan is authorized; the standard profile needs no privileges.",
	"RESOURCE_LIMIT":      "Narrow --roots or lower --max-files/--max-processes.",
	"REPORT_INCOMPATIBLE": "Compare two reports of the same host.",
}

func failure(code, op, target string, e error) error {
	d := diagnostics.New("cli", op, target, e)
	d.Code = code
	d.Recoverable = false
	// A wrapped engine error may already carry its code as a prefix.
	d.Cause = strings.TrimPrefix(d.Cause, code+": ")
	d.Impact = ""
	d.Remediation = cliHints[code]
	return d
}
func WriteError(w io.Writer, e error, jsonMode bool) {
	var x *ExitError
	if errors.As(e, &x) && x.Err == nil {
		return
	}
	if jsonMode {
		var d domain.Diagnostic
		if !errors.As(e, &d) {
			d = diagnostics.New("cli", "execute", "command", e)
			d.Recoverable = false
		}
		_ = json.NewEncoder(w).Encode(d)
	} else {
		var d domain.Diagnostic
		if errors.As(e, &d) && d.Component == "cli" {
			text := fmt.Sprintf("lasa: %s: %s", d.Code, d.Cause)
			if d.Target != "" {
				text += " [" + d.Operation + " " + d.Target + "]"
			}
			_, _ = fmt.Fprintln(w, report.Safe(text))
			if d.Remediation != "" {
				_, _ = fmt.Fprintln(w, "  hint: "+report.Safe(d.Remediation))
			}
			return
		}
		_, _ = fmt.Fprintln(w, report.Safe(e.Error()))
	}
}
func New(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "lasa", Short: "Evidence-backed, local Linux attack surface analysis", SilenceErrors: true, SilenceUsage: true, Version: domain.Version}
	root.SetOut(out)
	root.SetErr(errOut)
	root.PersistentFlags().String("diagnostics-format", "text", "stderr diagnostics: text or json")
	root.PersistentFlags().String("color", "auto", "terminal color: auto (terminals only; honors NO_COLOR), always or never")
	root.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		f, _ := c.Flags().GetString("diagnostics-format")
		if f != "text" && f != "json" {
			return failure("CONFIG_INVALID", "validate", "diagnostics-format", fmt.Errorf("expected text or json"))
		}
		if mode, _ := c.Flags().GetString("color"); mode != "auto" && mode != "always" && mode != "never" {
			return failure("CONFIG_INVALID", "validate", "--color", fmt.Errorf("expected auto, always or never, got %q", mode))
		}
		return nil
	}
	root.AddCommand(manCommand(), scanCommand(), doctorCommand(), reportCommand(), explainCommand(), diffCommand(), rulesCommand(), daemonCommand(), &cobra.Command{Use: "version", Short: "Print scanner version", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		_, e := fmt.Fprintln(c.OutOrStdout(), domain.Version)
		return e
	}})
	return root
}
func loadRules(path string) ([]rules.Rule, error) {
	pack, e := rules.Load(bytes.NewReader(builtin.YAML))
	if e != nil {
		return nil, e
	}
	if path == "" {
		return pack, nil
	}
	b, e := storage.Read(path, 1<<20)
	if e != nil {
		return nil, failure("CONFIG_INVALID", "read_rules", path, e)
	}
	custom, e := rules.Load(bytes.NewReader(b))
	if e != nil {
		return nil, failure("CONFIG_INVALID", "load_rules", path, e)
	}
	ids := map[string]bool{}
	for _, r := range pack {
		ids[r.ID] = true
	}
	for _, r := range custom {
		if ids[r.ID] {
			return nil, failure("CONFIG_INVALID", "load_rules", path, fmt.Errorf("duplicate builtin ID %s", r.ID))
		}
		pack = append(pack, r)
	}
	if len(pack) > 256 {
		return nil, fmt.Errorf("combined rule budget exceeds 256")
	}
	return pack, nil
}
func configFlags(c *cobra.Command, cfg *config.Config) {
	f := c.Flags()
	f.StringVar(&cfg.Profile, "profile", cfg.Profile, "standard, deep (explicit UID 0), container or sensor")
	f.DurationVar(&cfg.SensorDuration, "sensor-duration", cfg.SensorDuration, "optional sensor observation window (1ms..10m)")
	f.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "cooperative scan deadline")
	f.IntVar(&cfg.Workers, "workers", cfg.Workers, "bounded process workers (1..32)")
	f.IntVar(&cfg.MaxProcesses, "max-processes", cfg.MaxProcesses, "maximum visible PIDs to inspect")
	f.IntVar(&cfg.MaxFDs, "max-fds", cfg.MaxFDs, "maximum descriptors per PID")
	f.IntVar(&cfg.MaxFiles, "max-files", cfg.MaxFiles, "maximum scoped filesystem entries")
	f.StringSliceVar(&cfg.Roots, "roots", cfg.Roots, "explicit metadata roots (replaces defaults; comma-separated)")
}
func validFormat(format string) bool {
	return format == "json" || format == "terminal" || format == "html" || format == "sarif"
}
func prepare(c *config.Config, path string) (application.Engine, error) {
	// Relative roots are resolved against the working directory; absolute
	// roots must already be normalized so traversal is never rewritten.
	for i, root := range c.Roots {
		if root != "" && !filepath.IsAbs(root) {
			if absolute, e := filepath.Abs(root); e == nil {
				c.Roots[i] = absolute
			}
		}
	}
	if e := c.Validate(); e != nil {
		return application.Engine{}, failure("CONFIG_INVALID", "validate", "scan configuration", e)
	}
	pack, e := loadRules(path)
	if e != nil {
		return application.Engine{}, e
	}
	engine, e := application.Linux(*c, pack)
	if e != nil {
		var diagnostic domain.Diagnostic
		if errors.As(e, &diagnostic) {
			return engine, diagnostic
		}
		code := "HOST_UNSUPPORTED"
		if c.Profile == "deep" && os.Geteuid() != 0 {
			code = "PERMISSION_DENIED"
		}
		return engine, failure(code, "initialize", "Linux scanner", e)
	}
	return engine, nil
}
func write(c *cobra.Command, b []byte, path string) error {
	if path != "" {
		if e := storage.Atomic(path, b); e != nil {
			return failure("OUTPUT_WRITE_FAILED", "persist", path, e)
		}
		return nil
	}
	b = append(b, '\n')
	if _, e := c.OutOrStdout().Write(b); e != nil {
		return failure("OUTPUT_WRITE_FAILED", "write", "stdout", e)
	}
	return nil
}
func renderFailure(format string, e error) error {
	code := "RENDER_FAILED"
	if errors.Is(e, report.ErrExportLimit) {
		code = "RESOURCE_LIMIT"
	}
	return failure(code, "render", format+" report", e)
}

// readReport reads a saved JSON report from a regular file, or from standard
// input when path is "-", with the same size limit and validation.
func readReport(c *cobra.Command, path string) (domain.Snapshot, error) {
	var b []byte
	var e error
	if path == "-" {
		b, e = io.ReadAll(io.LimitReader(c.InOrStdin(), report.MaxInput+1))
		if e == nil && len(b) > report.MaxInput {
			e = fmt.Errorf("input exceeds %d bytes", report.MaxInput)
		}
		path = "standard input"
	} else {
		b, e = storage.Read(path, report.MaxInput)
	}
	if e != nil {
		return domain.Snapshot{}, failure("REPORT_READ_FAILED", "read_report", path, e)
	}
	s, e := report.Decode(b)
	if e != nil {
		return s, failure("REPORT_INVALID", "decode", path, e)
	}
	return s, nil
}
func scanCommand() *cobra.Command {
	cfg := config.Default()
	var format, output, custom, policy, threshold string
	var strict bool
	c := &cobra.Command{Use: "scan", Short: "Collect and correlate bounded, read-only local Linux metadata", Example: "  lasa scan\n  lasa scan --format json --output scan.json\n  lasa scan --profile container --strict --timeout 15s", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if !validFormat(format) {
			return failure("CONFIG_INVALID", "validate", "--format", fmt.Errorf("unsupported format %q; use terminal, json, html or sarif", format))
		}
		if threshold != "" && rules.SeverityRank(threshold) < 0 {
			return failure("CONFIG_INVALID", "validate", "--fail-on", fmt.Errorf("invalid severity %q; use informational, low, medium, high or critical", threshold))
		}
		var p application.Policy
		if policy != "" {
			b, e := storage.Read(policy, 1<<20)
			if e != nil {
				return failure("CONFIG_INVALID", "read_policy", policy, e)
			}
			p, e = application.ParsePolicy(b)
			if e != nil {
				return failure("CONFIG_INVALID", "parse_policy", policy, e)
			}
		}
		engine, e := prepare(&cfg, custom)
		if e != nil {
			return e
		}
		s, e := engine.Scan(c.Context(), cfg)
		if e != nil {
			return failure("SCAN_FAILED", "scan", "local host", e)
		}
		application.ApplyPolicy(&s, p, time.Now().UTC())
		b, e := renderReport(c, s, format, output)
		if e != nil {
			return renderFailure(format, e)
		}
		if e = write(c, b, output); e != nil {
			return e
		}
		if c.Context().Err() != nil {
			return &ExitError{130, c.Context().Err()}
		}
		if strict && !s.Complete {
			return &ExitError{3, nil}
		}
		for _, f := range s.Findings {
			if threshold != "" && !f.Suppressed && rules.SeverityRank(f.Severity) >= rules.SeverityRank(threshold) {
				return &ExitError{1, nil}
			}
		}
		return nil
	}}
	configFlags(c, &cfg)
	c.Flags().StringVar(&format, "format", "terminal", "terminal, json, html or sarif")
	c.Flags().StringVar(&output, "output", "", "private atomic report destination; parent must exist and contain no symlinks")
	c.Flags().StringVar(&custom, "rules", "", "explicit local custom YAML rule pack (adds to builtins)")
	c.Flags().StringVar(&policy, "suppressions", "", "local versioned JSON suppression policy")
	c.Flags().StringVar(&threshold, "fail-on", "", "exit 1 for an unsuppressed finding at or above severity")
	c.Flags().BoolVar(&strict, "strict", false, "exit 3 if collection is incomplete, after writing report")
	return c
}
func reportCommand() *cobra.Command {
	var input, format, output string
	c := &cobra.Command{Use: "report", Short: "Render a saved report without rescanning", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		s, e := readReport(c, input)
		if e != nil {
			return e
		}
		b, e := renderReport(c, s, format, output)
		if e != nil {
			return renderFailure(format, e)
		}
		return write(c, b, output)
	}}
	c.Flags().StringVar(&input, "input", "", "saved JSON report, or - for standard input")
	c.Flags().StringVar(&format, "format", "terminal", "terminal, json, html or sarif")
	c.Flags().StringVar(&output, "output", "", "private atomic destination")
	_ = c.MarkFlagRequired("input")
	return c
}
func explainCommand() *cobra.Command {
	var input, format string
	c := &cobra.Command{Use: "explain <finding-id>", Short: "Explain a finding and its recorded evidence", Long: "Explain a finding and its recorded evidence.\n\nThe finding can be named by its full fingerprint, a unique prefix of at least 6 characters (as shown by lasa report), or its rule ID when the report has exactly one finding for that rule. Use --report - to read the report from standard input.", Example: "  lasa explain 5601ae00 --report host.report.json\n  lasa explain LASA-013 --report host.report.json --format json", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		s, e := readReport(c, input)
		if e != nil {
			return e
		}
		f, e := findFinding(s, args[0], input)
		if e != nil {
			return e
		}
		{
			ids := map[string]bool{}
			for _, id := range f.Evidence {
				ids[id] = true
			}
			var obs []domain.Observation
			for _, o := range s.Observations {
				if ids[o.ID] {
					obs = append(obs, o)
				}
			}
			var eval []domain.Evaluation
			for _, v := range s.Evaluations {
				if v.RuleID == f.RuleID && v.Subject == f.Subject {
					eval = append(eval, v)
				}
			}
			if format == "json" {
				b, e := json.MarshalIndent(map[string]any{"schema": "lasa.explanation/v1", "finding": f, "observations": obs, "evaluations": eval}, "", "  ")
				if e != nil {
					return e
				}
				return write(c, b, "")
			}
			if format != "terminal" {
				return fmt.Errorf("explain format must be terminal or json")
			}
			return write(c, report.RenderExplanation(s, f, obs, eval, terminalOptions(c)), "")
		}
	}}
	c.Flags().StringVar(&input, "report", "", "saved JSON report, or - for standard input")
	c.Flags().StringVar(&format, "format", "terminal", "terminal or json")
	_ = c.MarkFlagRequired("report")
	return c
}
func diffCommand() *cobra.Command {
	var format, failOnNew string
	c := &cobra.Command{Use: "diff <previous-report> <current-report>", Short: "Compare fingerprints without treating missing evidence as resolution", Example: "  lasa diff before.json after.json\n  lasa diff before.json after.json --format terminal\n  lasa diff before.json after.json --fail-on-new high", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, args []string) error {
		if format != "json" && format != "terminal" {
			return failure("CONFIG_INVALID", "validate", "--format", fmt.Errorf("unsupported format %q; use json or terminal", format))
		}
		if failOnNew != "" && rules.SeverityRank(failOnNew) < 0 {
			return failure("CONFIG_INVALID", "validate", "--fail-on-new", fmt.Errorf("invalid severity %q; use informational, low, medium, high or critical", failOnNew))
		}
		if args[0] == "-" && args[1] == "-" {
			return failure("CONFIG_INVALID", "validate", "diff inputs", fmt.Errorf("only one report can be read from standard input"))
		}
		a, e := readReport(c, args[0])
		if e != nil {
			return e
		}
		b, e := readReport(c, args[1])
		if e != nil {
			return e
		}
		d, e := application.Diff(a, b)
		if e != nil {
			return failure("REPORT_INCOMPATIBLE", "diff", "reports", e)
		}
		var raw []byte
		if format == "terminal" {
			raw = report.RenderDiff(a, b, report.DiffView{New: d.New, Changed: d.Changed, Resolved: d.Resolved, Unknown: d.Unknown, Continuing: len(d.Continuing), UnknownReasons: d.UnknownReasons}, terminalOptions(c))
		} else if raw, e = json.MarshalIndent(d, "", "  "); e != nil {
			return e
		}
		if e = write(c, raw, ""); e != nil {
			return e
		}
		for _, f := range d.New {
			if failOnNew != "" && !f.Suppressed && rules.SeverityRank(f.Severity) >= rules.SeverityRank(failOnNew) {
				return &ExitError{1, nil}
			}
		}
		return nil
	}}
	c.Flags().StringVar(&format, "format", "json", "json or terminal")
	c.Flags().StringVar(&failOnNew, "fail-on-new", "", "exit 1 when a new unsuppressed finding is at or above this severity")
	return c
}
func rulesCommand() *cobra.Command {
	root := &cobra.Command{Use: "rules", Short: "Inspect reviewed builtin and explicitly supplied local rules"}
	var format, path string
	c := &cobra.Command{Use: "list", Short: "List rule versions, categories, conditions and remediation", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		pack, e := loadRules(path)
		if e != nil {
			return e
		}
		if format == "json" {
			b, e := json.MarshalIndent(rules.Pack{Schema: rules.Schema, Rules: pack}, "", "  ")
			if e != nil {
				return e
			}
			return write(c, b, "")
		}
		if format != "terminal" {
			return failure("CONFIG_INVALID", "validate", "--format", fmt.Errorf("unsupported format %q; use terminal or json", format))
		}
		for _, r := range pack {
			if _, e = fmt.Fprintf(c.OutOrStdout(), "%s v%s [%s/%s] %s\n  %s\n", report.Safe(r.ID), r.Version, report.Safe(r.Category), r.Severity, report.Safe(r.Title), report.Safe(r.Description)); e != nil {
				return e
			}
		}
		return nil
	}}
	c.Flags().StringVar(&format, "format", "terminal", "terminal or json")
	c.Flags().StringVar(&path, "rules", "", "explicit additional local YAML pack")
	validate := &cobra.Command{Use: "validate <pack.yaml>", Short: "Check a local rule pack without scanning", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		builtinPack, e := loadRules("")
		if e != nil {
			return e
		}
		pack, e := loadRules(args[0])
		if e != nil {
			return e
		}
		ids := make([]string, 0, len(pack)-len(builtinPack))
		for _, r := range pack[len(builtinPack):] {
			ids = append(ids, r.ID)
		}
		_, e = fmt.Fprintf(c.OutOrStdout(), "%s: valid, %d custom rules (%s) alongside %d builtin rules\n", report.Safe(args[0]), len(ids), report.Safe(strings.Join(ids, ", ")), len(builtinPack))
		return e
	}}
	var predicateFormat string
	predicates := &cobra.Command{Use: "predicates", Short: "List predicates available to rule conditions", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		list := rules.Predicates()
		if predicateFormat == "json" {
			b, e := json.MarshalIndent(list, "", "  ")
			if e != nil {
				return e
			}
			return write(c, b, "")
		}
		if predicateFormat != "terminal" {
			return failure("CONFIG_INVALID", "validate", "--format", fmt.Errorf("unsupported format %q; use terminal or json", predicateFormat))
		}
		var b strings.Builder
		for _, p := range list {
			fmt.Fprintf(&b, "%-27s %-7s %-7s %s\n", p.Name, p.Subject, p.Type, p.Description)
		}
		return write(c, []byte(strings.TrimSuffix(b.String(), "\n")), "")
	}}
	predicates.Flags().StringVar(&predicateFormat, "format", "terminal", "terminal or json")
	root.AddCommand(c, validate, predicates)
	return root
}
func daemonCommand() *cobra.Command {
	cfg := config.Default()
	var dir, custom, policy string
	var interval time.Duration
	var retention int
	c := &cobra.Command{Use: "daemon", Short: "Run sequential scheduled scans with private atomic snapshots", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		engine, e := prepare(&cfg, custom)
		if e != nil {
			return e
		}
		var p application.Policy
		if policy != "" {
			b, e := storage.Read(policy, 1<<20)
			if e != nil {
				return e
			}
			p, e = application.ParsePolicy(b)
			if e != nil {
				return e
			}
		}
		d := application.Daemon{Directory: dir, Interval: interval, Retention: retention, Log: c.ErrOrStderr(), Scan: func(ctx context.Context) (domain.Snapshot, error) {
			s, e := engine.Scan(ctx, cfg)
			if e == nil {
				application.ApplyPolicy(&s, p, time.Now().UTC())
			}
			return s, e
		}}
		if e = d.Run(c.Context()); e != nil {
			return failure("DAEMON_FAILED", "run", dir, e)
		}
		return nil
	}}
	configFlags(c, &cfg)
	defaultDir := "./lasa-state"
	if home, e := os.UserHomeDir(); e == nil {
		defaultDir = filepath.Join(home, ".local", "state", "lasa")
	}
	c.Flags().StringVar(&dir, "state-dir", defaultDir, "private directory for lock and retained JSON snapshots")
	c.Flags().DurationVar(&interval, "interval", 15*time.Minute, "delay between completed scans (minimum 1s)")
	c.Flags().IntVar(&retention, "retention", 96, "maximum retained LASA snapshots (1..10000)")
	c.Flags().StringVar(&custom, "rules", "", "explicit local custom rule pack")
	c.Flags().StringVar(&policy, "suppressions", "", "local suppression policy, loaded at startup")
	return c
}

// findFinding resolves a full fingerprint, a unique case-insensitive prefix of
// at least six characters, or a rule ID with exactly one finding.
func findFinding(s domain.Snapshot, query, source string) (domain.Finding, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	var matches []domain.Finding
	for _, f := range s.Findings {
		if strings.ToLower(f.ID) == q {
			return f, nil
		}
	}
	for _, f := range s.Findings {
		if strings.EqualFold(f.RuleID, q) || len(q) >= 6 && strings.HasPrefix(strings.ToLower(f.ID), q) {
			matches = append(matches, f)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		if len(q) < 6 {
			return domain.Finding{}, failure("FINDING_NOT_FOUND", "explain", query, fmt.Errorf("no finding or rule ID matches in %s; prefixes need at least 6 characters", source))
		}
		return domain.Finding{}, failure("FINDING_NOT_FOUND", "explain", query, fmt.Errorf("no finding matches in %s", source))
	}
	short := report.ShortIDs(matches)
	var ids []string
	for _, f := range matches[:min(10, len(matches))] {
		ids = append(ids, short[f.ID])
	}
	return domain.Finding{}, failure("FINDING_AMBIGUOUS", "explain", query, fmt.Errorf("%d findings match: %s", len(matches), strings.Join(ids, ", ")))
}
