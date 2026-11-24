package report

import (
	"fmt"
	"strings"
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
	"critical":      "1;37;41",
	"high":          "1;31",
	"medium":        "1;33",
	"low":           "1;36",
	"informational": "2",
}

var severityOrder = []string{"critical", "high", "medium", "low", "informational"}

func newTerminal(options TerminalOptions) *terminalReport {
	width := options.Width
	if width <= 0 {
		width = 100
	}
	return &terminalReport{width: min(140, max(32, width)), color: options.Color}
}

func renderTerminal(s domain.Snapshot, options TerminalOptions) []byte {
	t := newTerminal(options)
	v := newView(s)
	ids := ShortIDs(s.Findings)
	t.header(s)
	t.summary(s)
	if len(s.Findings) > 0 {
		t.table(v, s.Findings, ids)
		t.section("Details")
		common := commonWarnings(s.Findings)
		for _, f := range s.Findings {
			t.details(v, f, ids[f.ID], common)
		}
	}
	t.gaps(s)
	t.notes(s)
	return []byte(t.String())
}

func (t *terminalReport) header(s domain.Snapshot) {
	scan := s.ScanID
	if len(scan) > 8 {
		scan = scan[:8]
	}
	line := fmt.Sprintf("LASA %s · %s profile · scan %s", domain.Version, s.Profile, scan)
	if !s.Started.IsZero() {
		line += " · " + s.Started.UTC().Format("2006-01-02 15:04 UTC")
	}
	t.styled("1", "", "  ", line)
	t.wrapped("", "", fmt.Sprintf("Scope: %d processes · %d sockets · %d files", len(s.Processes), len(s.Sockets), len(s.Files)))
	coverage := t.style("1;32", "complete")
	if !s.Complete {
		coverage = t.style("1;33", "partial") + " (see Collection gaps)"
	}
	t.WriteString("Coverage: " + coverage + "\n")
}

func (t *terminalReport) summary(s domain.Snapshot) {
	t.section("Findings")
	if len(s.Findings) == 0 {
		msg := "No findings in the collected evidence."
		if !s.Complete {
			msg += " Coverage is partial, so this is not a clean bill of health."
		}
		t.wrapped("  ", "  ", msg)
		return
	}
	counts := map[string]int{}
	suppressed := 0
	for _, f := range s.Findings {
		counts[f.Severity]++
		if f.Suppressed {
			suppressed++
		}
	}
	var parts []string
	for _, sev := range severityOrder {
		if counts[sev] > 0 {
			parts = append(parts, t.style(severityColors[sev], fmt.Sprintf("%d %s", counts[sev], sev)))
		}
	}
	t.WriteString(fmt.Sprintf("  %d total: %s · %d suppressed\n\n", len(s.Findings), strings.Join(parts, ", "), suppressed))
}

func (t *terminalReport) table(v view, findings []domain.Finding, ids map[string]string) {
	idWidth := 8
	for _, id := range ids {
		idWidth = max(idWidth, len(id))
	}
	const sevWidth, priWidth = 8, 3
	fixed := 2 + idWidth + 2 + sevWidth + 2 + priWidth + 2
	space := t.width - fixed - 2
	if space < 40 {
		// Stacked layout for narrow terminals: no column truncation.
		for _, f := range findings {
			t.WriteString("  " + t.style("2", Safe(ids[f.ID])) + "  " + t.severity(f.Severity, 0) + fmt.Sprintf("  %d\n", f.Priority))
			t.wrapped("    ", "    ", title(f))
			t.wrapped("    ", "    ", v.subject(f))
		}
		return
	}
	titleWidth := max(20, space*45/100)
	subjectWidth := space - titleWidth
	head := fmt.Sprintf("  %-*s  %-*s  %*s  %-*s  %s", idWidth, "ID", sevWidth, "SEVERITY", priWidth, "PRI", titleWidth, "FINDING", "AFFECTED")
	t.WriteString(t.style("1", head) + "\n")
	for _, f := range findings {
		row := fmt.Sprintf("  %s  %s  %*d  %s  %s",
			t.style("2", fmt.Sprintf("%-*s", idWidth, Safe(ids[f.ID]))),
			t.severity(f.Severity, sevWidth), priWidth, f.Priority,
			pad(truncateRight(Safe(title(f)), titleWidth), titleWidth),
			truncateLeft(Safe(v.subject(f)), subjectWidth))
		t.WriteString(strings.TrimRight(row, " ") + "\n")
	}
}

func title(f domain.Finding) string {
	if f.Suppressed {
		return f.Title + " [suppressed]"
	}
	return f.Title
}

func (t *terminalReport) details(v view, f domain.Finding, id string, common map[string]bool) {
	t.WriteByte('\n')
	t.wrapped(t.severity(f.Severity, 0)+"  ", "  ", f.Title)
	t.field("ID", id+" (rule "+f.RuleID+" v"+f.RuleVersion+")")
	t.field("Affected", v.subject(f))
	t.field("Why", v.why(f))
	if f.Suppressed {
		status := "suppressed"
		if f.SuppressionReason != "" {
			status += ": " + f.SuppressionReason
		}
		t.field("Status", status)
	}
	t.field("Risk", f.Path.ConditionalStep)
	if f.Path.PotentialImpact != "" && f.Path.PotentialImpact != f.Description && f.Path.PotentialImpact != f.Path.ConditionalStep {
		t.field("Impact", f.Path.PotentialImpact)
	}
	t.field("Requires", strings.Join(f.Prerequisites, " "))
	t.field("Fix", f.Remediation)
	if cmd := v.suggestion(f); cmd != "" {
		// Commands are never wrapped so they stay copyable; suggestion only
		// offers paths that need no display escaping.
		t.field("Suggested", "review first; LASA never runs commands")
		t.WriteString("              " + t.style("1", "$ "+cmd) + "\n")
	}
	t.field("Assessment", fmt.Sprintf("priority %d/100 · confidence %s · exposure %s", f.Priority, f.Confidence, v.exposure(f)))
	for _, w := range f.Warnings {
		if !common[w] {
			t.field("Caveat", w)
		}
	}
}

func (t *terminalReport) gaps(s domain.Snapshot) {
	groups := groupDiagnostics(s.Diagnostics)
	var gaps, expected []diagnosticGroup
	for _, g := range groups {
		if g.Expected {
			expected = append(expected, g)
		} else {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) > 0 {
		t.section("Collection gaps")
		t.dim("  ", "  ", "Checks LASA could not complete. Unknown never counts as secure.")
		for _, g := range gaps {
			t.group(g, true)
		}
	}
	if len(expected) > 0 {
		t.section("Not inspected by design")
		for _, g := range expected {
			t.group(g, false)
		}
	}
	if len(s.Diagnostics) > 0 {
		t.dim("  ", "  ", fmt.Sprintf("%d diagnostics in total; use --format json for the complete list.", len(s.Diagnostics)))
	}
}

func (t *terminalReport) group(g diagnosticGroup, action bool) {
	examples := make([]string, len(g.Examples))
	for i, e := range g.Examples {
		examples[i] = truncateLeft(Safe(e), 48)
	}
	more := ""
	if g.Count > len(g.Examples) {
		more = ", …"
	}
	t.wrapped(fmt.Sprintf("  %-11s ", Safe(g.Component)), strings.Repeat(" ", 14), fmt.Sprintf("%d %s (e.g. %s%s)", g.Count, g.Summary, strings.Join(examples, ", "), more))
	if action && g.Action != "" {
		t.wrapped(strings.Repeat(" ", 14)+"→ ", strings.Repeat(" ", 16), g.Action)
	}
}

func (t *terminalReport) notes(s domain.Snapshot) {
	common := commonWarnings(s.Findings)
	if len(common) == 0 {
		return
	}
	t.section("Notes")
	for _, f := range s.Findings {
		for _, w := range f.Warnings {
			if common[w] {
				t.wrapped("  • ", "    ", w)
				delete(common, w)
			}
		}
	}
}

// RenderExplanation renders one finding with its recorded evidence and the
// coverage of the collectors that supplied it.
func RenderExplanation(s domain.Snapshot, f domain.Finding, observations []domain.Observation, evaluations []domain.Evaluation, options TerminalOptions) []byte {
	t := newTerminal(options)
	v := newView(s)
	t.header(s)
	t.details(v, f, f.ID, nil)
	t.section("Recorded evidence")
	for _, o := range observations {
		t.wrapped("  ", "    ", fmt.Sprintf("%s = %s (%s, %s collector)", o.Key, o.Value, o.State, o.Collector))
		t.dim("    ", "    ", "source "+o.Source+" · id "+o.ID)
	}
	if len(evaluations) > 0 {
		t.section("Rule evaluation")
		for _, e := range evaluations {
			t.wrapped("  ", "    ", fmt.Sprintf("%s: %s", e.State, e.Reason))
		}
	}
	collectors := map[string]bool{}
	for _, o := range observations {
		collectors[o.Collector] = true
	}
	var relevant []domain.Coverage
	for _, c := range s.Coverage {
		if collectors[c.Collector] {
			relevant = append(relevant, c)
		}
	}
	if len(relevant) > 0 {
		t.section("Coverage of these collectors")
		for _, c := range relevant {
			status := "complete"
			if !c.Complete {
				status = "partial"
			}
			t.wrapped("  ", "    ", fmt.Sprintf("%s: %s · %d attempted, %d successful, %d skipped, %d not applicable, %d inconclusive", c.Collector, status, c.Attempted, c.Successful, c.Skipped, c.Unsupported, c.Inconclusive))
		}
	}
	return []byte(t.String())
}

func (t *terminalReport) severity(sev string, width int) string {
	text := strings.ToUpper(Safe(sev))
	if width > 0 {
		text = fmt.Sprintf("%-*s", width, text)
	}
	return t.style(severityColors[sev], text)
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
		fmt.Fprintln(&t.Builder, "  "+t.style("2", label))
		t.wrapped("    ", "    ", value)
		return
	}
	t.wrapped("  "+t.style("2", fmt.Sprintf("%-11s", label))+" ", "              ", value)
}

func truncateRight(s string, width int) string {
	if utf8.RuneCountInString(s) <= width {
		return s
	}
	r := []rune(s)
	return string(r[:max(0, width-1)]) + "…"
}

func truncateLeft(s string, width int) string {
	if utf8.RuneCountInString(s) <= width {
		return s
	}
	r := []rune(s)
	return "…" + string(r[len(r)-max(0, width-1):])
}

func pad(s string, width int) string {
	return s + strings.Repeat(" ", max(0, width-utf8.RuneCountInString(s)))
}

// dim wraps value and renders each line in the secondary style.
func (t *terminalReport) dim(prefix, indent, value string) { t.styled("2", prefix, indent, value) }

// styled wraps value and applies a formatter-owned style to each line.
func (t *terminalReport) styled(code, prefix, indent, value string) {
	var inner terminalReport
	inner.width, inner.color = t.width, false
	inner.wrapped(prefix, indent, value)
	for _, line := range strings.SplitAfter(strings.TrimSuffix(inner.String(), "\n"), "\n") {
		line = strings.TrimSuffix(line, "\n")
		lead := len(line) - len(strings.TrimLeft(line, " "))
		t.WriteString(line[:lead] + t.style(code, line[lead:]) + "\n")
	}
}

// visible measures printed width, ignoring formatter-owned color escapes.
func visible(s string) int {
	n, escape := 0, false
	for _, r := range s {
		switch {
		case escape:
			escape = r != 'm'
		case r == '\x1b':
			escape = true
		default:
			n++
		}
	}
	return n
}

// wrapped prefers word boundaries and keeps long values visible by splitting
// them at rune boundaries. The continuation indent is the visible prefix width.
func (t *terminalReport) wrapped(prefix, indent, value string) {
	value = Safe(value)
	width := max(1, t.width-max(visible(prefix), visible(indent)))
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
