package report

import (
	"fmt"

	"github.com/jasonachkar/lasa/internal/domain"
)

// DiffView is the presentation input for a snapshot comparison.
type DiffView struct {
	New, Changed, Resolved, Unknown []domain.Finding
	Continuing                      int
	UnknownReasons                  map[string]string
}

// RenderDiff renders a comparison for people; JSON remains the interchange form.
func RenderDiff(previous, current domain.Snapshot, d DiffView, options TerminalOptions) []byte {
	t := newTerminal(options)
	before, after := newView(previous), newView(current)
	t.styled("1", "", "  ", fmt.Sprintf("LASA diff · %s → %s", short(previous.ScanID), short(current.ScanID)))
	t.wrapped("", "", fmt.Sprintf("%d new · %d changed · %d resolved · %d unknown · %d continuing", len(d.New), len(d.Changed), len(d.Resolved), len(d.Unknown), d.Continuing))
	all := append(append(append(append([]domain.Finding{}, d.New...), d.Changed...), d.Resolved...), d.Unknown...)
	ids := ShortIDs(all)
	section := func(title string, findings []domain.Finding, v view, reasons bool) {
		if len(findings) == 0 {
			return
		}
		t.section(title)
		for _, f := range findings {
			t.wrapped("  "+t.style("2", Safe(ids[f.ID]))+"  "+t.severity(f.Severity, 8)+"  ", "              ", f.Title+" · "+v.subject(f))
			if reasons && d.UnknownReasons[f.ID] != "" {
				t.dim("              ", "              ", "why unknown: "+d.UnknownReasons[f.ID])
			}
		}
	}
	section("New", d.New, after, false)
	section("Changed", d.Changed, after, false)
	section("Resolved", d.Resolved, before, false)
	section("Unknown (absent but not verified as resolved)", d.Unknown, before, true)
	return []byte(t.String())
}

func short(id string) string {
	return Safe(id[:min(8, len(id))])
}
