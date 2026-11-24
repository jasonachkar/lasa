package report

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/jasonachkar/lasa/internal/domain"
)

// TerminalOptions controls presentation without changing the report data.
type TerminalOptions struct {
	Width int
	Color bool
}

// RenderTerminal renders a report with the capabilities of its destination.
func RenderTerminal(s domain.Snapshot, options TerminalOptions) []byte {
	s.Sort()
	return renderTerminal(s, options)
}

type terminalReport struct {
	strings.Builder
	width int
	color bool
}

var severityColors = map[string]string{
	"critical":      "1;35",
	"high":          "1;31",
	"medium":        "1;33",
	"low":           "1;36",
	"informational": "1;34",
}

func renderTerminal(s domain.Snapshot, options TerminalOptions) []byte {
	width := options.Width
	if width <= 0 {
		width = 96
	}
	t := terminalReport{width: min(120, max(32, width)), color: options.Color}
	t.WriteString(t.style("1", "LASA "+Safe(domain.Version)) + "\n")
	t.field("Scan", s.ScanID)
	t.field("Profile", s.Profile)
	t.field("Scope", s.Host.Scope)
	t.field("Collection", coverageStatus(s.Complete)+" within declared scope")
	t.field("Observed", fmt.Sprintf("%d processes, %d sockets, %d files", len(s.Processes), len(s.Sockets), len(s.Files)))

	t.section("Findings")
	if len(s.Findings) == 0 {
		t.WriteString("  No findings in the collected evidence.\n")
	} else {
		t.findingsTable(s.Findings)
		t.findingDetails(s)
	}
	t.coverage(s.Coverage)
	if len(s.Diagnostics) > 0 {
		t.section(fmt.Sprintf("Diagnostics (%d)", len(s.Diagnostics)))
		limit := min(12, len(s.Diagnostics))
		for _, diagnostic := range s.Diagnostics[:limit] {
			t.wrapped("  ", "  ", diagnostic.Error())
		}
		if limit < len(s.Diagnostics) {
			t.wrapped("  ", "  ", fmt.Sprintf("Showing %d of %d diagnostics. Use JSON for the full list.", limit, len(s.Diagnostics)))
		}
	}
	return []byte(t.String())
}

func (t *terminalReport) findingsTable(findings []domain.Finding) {
	suppressed := 0
	for _, finding := range findings {
		if finding.Suppressed {
			suppressed++
		}
	}
	t.wrapped("  ", "  ", fmt.Sprintf("%d total, %d suppressed", len(findings), suppressed))
	numberWidth := len(strconv.Itoa(len(findings)))
	showPriority := t.width >= 52
	header := fmt.Sprintf("%*s  %-13s  ", numberWidth, "#", "Severity")
	if showPriority {
		header += "Priority  "
	}
	t.WriteString(t.style("1", header+"Finding") + "\n")
	t.WriteString(strings.Repeat("-", t.width) + "\n")
	for i, finding := range findings {
		number := fmt.Sprintf("%*d  ", numberWidth, i+1)
		severity := fmt.Sprintf("%-13s", strings.ToUpper(Safe(finding.Severity)))
		columns := "  "
		if showPriority {
			columns += fmt.Sprintf("%8d  ", finding.Priority)
		}
		title := finding.Title
		if finding.Suppressed {
			title += " [suppressed]"
		}
		prefix := number + t.style(severityColors[finding.Severity], severity) + columns
		indent := strings.Repeat(" ", len(number)+utf8.RuneCountInString(severity)+len(columns))
		t.wrapped(prefix, indent, title)
	}
}

func (t *terminalReport) findingDetails(s domain.Snapshot) {
	t.section("Finding details")
	subjects := make(map[string]string, len(s.Graph.Nodes))
	for _, node := range s.Graph.Nodes {
		subjects[node.ID] = node.Label
	}
	for i, finding := range s.Findings {
		t.WriteByte('\n')
		severity := strings.ToUpper(Safe(finding.Severity))
		number := strconv.Itoa(i + 1)
		prefix := number + ". " + t.style(severityColors[finding.Severity], severity) + "  "
		indent := strings.Repeat(" ", len(number)+4+utf8.RuneCountInString(severity))
		t.wrapped(prefix, indent, finding.Title)

		t.field("Rule", finding.RuleID)
		t.field("Fingerprint", finding.ID)
		subject := subjects[finding.Subject]
		if subject == "" {
			subject = finding.Subject
		}
		t.field("Affected", subject)
		t.field("Assessment", fmt.Sprintf("Priority %d/100 | Confidence %s | Exposure %s", finding.Priority, finding.Confidence, finding.Exposure))
		if finding.Suppressed {
			status := "Suppressed"
			if finding.SuppressionReason != "" {
				status += " - " + finding.SuppressionReason
			}
			t.field("Status", status)
		}
		t.field("Description", finding.Description)
		t.field("Scenario", finding.Path.ConditionalStep)
		t.field("Impact", finding.Path.PotentialImpact)
		t.field("Remediation", finding.Remediation)
		t.field("Evidence", strings.Join(finding.Evidence, ", "))
		for _, warning := range finding.Warnings {
			t.field("Uncertainty", warning)
		}
	}
}

func (t *terminalReport) coverage(coverage []domain.Coverage) {
	if len(coverage) == 0 {
		return
	}
	t.section("Collection coverage")
	if t.width < 86 {
		for _, c := range coverage {
			t.wrapped("  ", "  ", fmt.Sprintf("%s: %s | %d attempted, %d successful, %d skipped, %d unsupported, %d inconclusive",
				c.Collector, coverageStatus(c.Complete), c.Attempted, c.Successful, c.Skipped, c.Unsupported, c.Inconclusive))
		}
		return
	}
	table := tabwriter.NewWriter(&t.Builder, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "  Collector\tAttempted\tSuccessful\tSkipped\tUnsupported\tInconclusive\tStatus")
	for _, c := range coverage {
		fmt.Fprintf(table, "  %s\t%d\t%d\t%d\t%d\t%d\t%s\n",
			Safe(c.Collector), c.Attempted, c.Successful, c.Skipped, c.Unsupported, c.Inconclusive, coverageStatus(c.Complete))
	}
	_ = table.Flush()
}

func coverageStatus(complete bool) string {
	if complete {
		return "Complete"
	}
	return "Partial"
}

func (t *terminalReport) style(code, text string) string {
	if t.color && code != "" {
		return "\x1b[" + code + "m" + text + "\x1b[0m"
	}
	return text
}

func (t *terminalReport) section(title string) {
	fmt.Fprintln(&t.Builder, "\n"+t.style("1", strings.ToUpper(title)))
}

func (t *terminalReport) field(label, value string) {
	if value == "" {
		return
	}
	if t.width < 50 {
		fmt.Fprintln(&t.Builder, "  "+label)
		t.wrapped("    ", "    ", value)
		return
	}
	t.wrapped(fmt.Sprintf("  %-13s ", label), "                ", value)
}

// wrapped prefers word boundaries and keeps long values visible by splitting
// them at rune boundaries. The continuation indent is the visible prefix width.
func (t *terminalReport) wrapped(prefix, indent, value string) {
	value = Safe(value)
	width := max(1, t.width-len(indent))
	for {
		end, next := len(value), len(value)
		space, column := -1, 0
		for offset, char := range value {
			if column == width {
				end, next = offset, offset
				if char == ' ' {
					next++
				} else if space > 0 {
					end, next = space, space+1
				}
				break
			}
			if char == ' ' {
				space = offset
			}
			column++
		}
		t.WriteString(prefix)
		t.WriteString(value[:end])
		t.WriteByte('\n')
		if next == len(value) {
			return
		}
		value, prefix = value[next:], indent
	}
}
