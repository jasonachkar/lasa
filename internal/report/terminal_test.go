package report

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
)

var updateTerminalGolden = flag.Bool("update-terminal", false, "refresh terminal output fixtures")

func TestTerminalGolden(t *testing.T) {
	for _, columns := range []int{44, 110} {
		t.Run(fmt.Sprint(columns), func(t *testing.T) {
			output := RenderTerminal(terminalFixture(), TerminalOptions{Width: columns})
			_, body, _ := strings.Cut(string(output), "\n")
			// The version banner is release-specific; the layout fixture is not.
			output = []byte("LASA VERSION\n" + body)
			path := filepath.Join("testdata", fmt.Sprintf("terminal-%d.golden", columns))
			if *updateTerminalGolden {
				if err := os.WriteFile(path, output, 0644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(output) != string(want) {
				t.Fatalf("terminal output differs from %s\n%s", path, output)
			}
		})
	}
}

func terminalFixture() domain.Snapshot {
	common := "Conditional scenario: no vulnerability, successful compromise, or exploitation has been established."
	return domain.Snapshot{
		ScanID:    "0123456789abcdef",
		Profile:   "standard",
		Graph:     domain.Graph{Nodes: []domain.Node{{ID: "file", Kind: "file", Label: "/etc/sudoers.d/evil"}, {ID: "proc", Kind: "process", Label: "/usr/bin/redis"}, {ID: "sock", Kind: "socket", Label: "tcp 0.0.0.0:6379"}}, Edges: []domain.Edge{{From: "proc", To: "sock", Type: "LISTENS_ON"}}},
		Files:     []domain.File{{ID: "file", Path: "/etc/sudoers.d/evil", Mode: 0o100666, UID: 1000, GID: 1000, Kind: "sudoers"}},
		Processes: []domain.Process{{ID: "proc", PID: 812, Executable: "/usr/bin/redis"}},
		Findings: []domain.Finding{
			{ID: "bbbbbbbb11111111", RuleID: "LASA-003", RuleVersion: "1", Title: "Local listener", Severity: "low", Priority: 15,
				Confidence: "medium", Exposure: domain.UnknownExposure, Subject: "proc",
				Suppressed: true, SuppressionReason: "Reviewed exception", Warnings: []string{common}},
			{ID: "aaaaaaaa22222222", RuleID: "LASA-009", RuleVersion: "1", Title: "Writable sudoers configuration",
				Severity: "high", Priority: 81, Confidence: "high", Exposure: domain.UnknownExposure,
				Subject: "file", Remediation: "Restrict write access.\x1b[9m", Description: "desc",
				Path:     domain.AttackPath{ConditionalStep: "An account can grant itself sudo.", PotentialImpact: "Root access."},
				Warnings: []string{common, "ACL visibility is incomplete."}},
		},
		Coverage: []domain.Coverage{{Collector: "filesystem", Attempted: 4, Successful: 3, Inconclusive: 1}},
		Diagnostics: []domain.Diagnostic{
			{Code: "PERMISSION_DENIED", Component: "process", Target: "/proc/1/fd", Remediation: "Run the deep profile."},
			{Code: "PERMISSION_DENIED", Component: "process", Target: "/proc/2/fd", Remediation: "Run the deep profile."},
			{Code: diagnostics.CodeSymlinkNotFollowed, Component: "filesystem", Target: "/usr/bin/awk"},
		},
	}
}

func TestTerminalFindings(t *testing.T) {
	s := terminalFixture()
	plain := string(RenderTerminal(s, TerminalOptions{Width: 140}))
	table, details, _ := strings.Cut(plain, "\nDETAILS\n")
	high, _, _ := strings.Cut(table, "Local listener")
	if !strings.Contains(high, "Writable sudoers") {
		t.Fatal("the findings table must list findings in priority order")
	}
	for _, want := range []string{
		"2 total: 1 high, 1 low · 1 suppressed", "aaaaaaaa", "/etc/sudoers.d/evil",
		"Local listener [suppressed]", "/usr/bin/redis (pid 812)",
	} {
		if !strings.Contains(table, want) {
			t.Errorf("findings table is missing %q", want)
		}
	}
	for _, want := range []string{
		"mode 0666 (rw-rw-rw-), owner uid 1000, group gid 1000; writable by any local user and members of group 1000",
		"listens on tcp 0.0.0.0:6379", "Reviewed exception", "An account can grant itself sudo.", "Root access.",
		"$ sudo chmod go-w -- '/etc/sudoers.d/evil' && sudo visudo -cf '/etc/sudoers.d/evil'",
		"exposure n/a", "ACL visibility is incomplete.", `Restrict write access.\x1b[9m`,
	} {
		if !strings.Contains(details, want) {
			t.Errorf("finding details are missing %q", want)
		}
	}
	if strings.Count(plain, "Conditional scenario") != 1 || !strings.Contains(plain, "\nNOTES\n") {
		t.Error("caveats shared by every finding must be printed once, in the notes")
	}
	gaps, design, _ := strings.Cut(plain, "NOT INSPECTED BY DESIGN")
	if !strings.Contains(gaps, "2 unreadable (permission denied) (e.g. /proc/1/fd, /proc/2/fd)") || !strings.Contains(gaps, "→ Run the deep profile.") {
		t.Error("collection gaps must be grouped with a count, examples and one action")
	}
	if !strings.Contains(design, "1 symbolic links not followed (by design)") || strings.Contains(gaps, "/usr/bin/awk") {
		t.Error("policy exclusions must be listed separately from collection gaps")
	}

	colored := string(RenderTerminal(s, TerminalOptions{Width: 140, Color: true}))
	if !strings.Contains(colored, "\x1b[1;31mHIGH") || !strings.Contains(colored, "\x1b[1;36mLOW") {
		t.Fatal("expected distinct colors for high and low severity")
	}
	if strings.Contains(colored, "\x1b[9m") || regexp.MustCompile(`\x1b\[[0-9;]+m`).ReplaceAllString(colored, "") != plain {
		t.Fatal("color must only add formatter-owned escapes")
	}

	for _, width := range []int{44, 80} {
		narrow := string(RenderTerminal(s, TerminalOptions{Width: width}))
		for _, line := range strings.Split(narrow, "\n") {
			if utf8.RuneCountInString(line) > width && !strings.Contains(line, "$ ") {
				t.Errorf("line exceeds %d columns: %q", width, line)
			}
		}
		if !strings.Contains(narrow, "/etc/sudoers.d/evil") {
			t.Errorf("affected resource must remain visible at width %d", width)
		}
	}
}

func TestCleanPartialScanIsNotPresentedAsSecure(t *testing.T) {
	out := string(RenderTerminal(domain.Snapshot{ScanID: "s"}, TerminalOptions{}))
	if !strings.Contains(out, "No findings") || !strings.Contains(out, "not a clean bill of health") || !strings.Contains(out, "partial") {
		t.Fatalf("an incomplete clean scan must say coverage is partial:\n%s", out)
	}
}

func TestShortIDsAreUniquePrefixes(t *testing.T) {
	ids := ShortIDs([]domain.Finding{{ID: "abcdef0011112222"}, {ID: "abcdef0099998888"}, {ID: "12345678aaaa"}})
	if ids["abcdef0011112222"] != "abcdef001111" || ids["abcdef0099998888"] != "abcdef009999" || ids["12345678aaaa"] != "12345678" {
		t.Fatalf("unexpected short IDs %v", ids)
	}
}
