package report

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestTerminalFindings(t *testing.T) {
	fingerprint := strings.Repeat("a", 32)
	s := domain.Snapshot{
		ScanID:  "fixture",
		Profile: "standard",
		Graph:   domain.Graph{Nodes: []domain.Node{{ID: "file", Label: "/etc/sudoers"}}},
		Findings: []domain.Finding{
			{ID: "low-id", Title: "Local listener", Severity: "low", Priority: 15,
				Suppressed: true, SuppressionReason: "Reviewed exception"},
			{ID: fingerprint, RuleID: "LASA-009", Title: "Writable sudoers configuration",
				Severity: "high", Priority: 81, Confidence: "high", Exposure: domain.UnknownExposure,
				Subject: "file", Remediation: "Restrict write access.\x1b[9m",
				Evidence: []string{"obs-1", "obs-2"}, Warnings: []string{"ACL visibility is incomplete."}},
		},
		Coverage: []domain.Coverage{{Collector: "filesystem", Attempted: 4, Successful: 3, Inconclusive: 1}},
	}
	plain := string(RenderTerminal(s, TerminalOptions{Width: 96}))
	table, _, _ := strings.Cut(plain, "\nFINDING DETAILS\n")
	beforeLow, _, hasLow := strings.Cut(table, "Local listener")
	if !hasLow || !strings.Contains(beforeLow, "Writable sudoers") {
		t.Fatal("the findings table must list each finding in priority order")
	}
	for _, want := range []string{
		"2 total, 1 suppressed", "Local listener [suppressed]", "Reviewed exception",
		"LASA-009", fingerprint, "/etc/sudoers", "Priority 81/100", "obs-1, obs-2",
		"ACL visibility is incomplete.", "Restrict write access.\\x1b[9m", "COLLECTION COVERAGE",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("terminal report is missing %q", want)
		}
	}
	colored := string(RenderTerminal(s, TerminalOptions{Width: 96, Color: true}))
	if !strings.Contains(colored, "\x1b[1;31mHIGH") || !strings.Contains(colored, "\x1b[1;36mLOW") {
		t.Fatal("expected distinct colors for high and low severity")
	}
	if strings.Contains(colored, "\x1b[9m") || regexp.MustCompile(`\x1b\[[0-9;]+m`).ReplaceAllString(colored, "") != plain {
		t.Fatal("color must only add formatter-owned escapes")
	}

	narrow := string(RenderTerminal(s, TerminalOptions{Width: 44}))
	if !strings.Contains(narrow, fingerprint) {
		t.Fatal("the fingerprint must remain copyable on a narrow terminal")
	}
	for _, line := range strings.Split(narrow, "\n") {
		if utf8.RuneCountInString(line) > 44 {
			t.Errorf("narrow terminal line exceeds 44 columns: %q", line)
		}
	}
}
