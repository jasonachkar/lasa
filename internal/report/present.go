package report

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
)

// view indexes a snapshot for presenting findings in human terms. It only
// reads saved report data; it never consults the scanned system.
type view struct {
	s       domain.Snapshot
	labels  map[string]string
	kinds   map[string]string
	files   map[string]domain.File
	process map[string]domain.Process
	sockets map[string][]string
}

func newView(s domain.Snapshot) view {
	v := view{s: s, labels: map[string]string{}, kinds: map[string]string{}, files: map[string]domain.File{}, process: map[string]domain.Process{}, sockets: map[string][]string{}}
	for _, n := range s.Graph.Nodes {
		v.labels[n.ID] = n.Label
		v.kinds[n.ID] = n.Kind
	}
	for _, f := range s.Files {
		v.files[f.ID] = f
	}
	for _, p := range s.Processes {
		v.process[p.ID] = p
	}
	for _, e := range s.Graph.Edges {
		if e.Type == "LISTENS_ON" {
			v.sockets[e.From] = append(v.sockets[e.From], v.labels[e.To])
		}
	}
	for id := range v.sockets {
		sort.Strings(v.sockets[id])
	}
	return v
}

// subject is the human label of a finding's affected resource.
func (v view) subject(f domain.Finding) string {
	if p, ok := v.process[f.Subject]; ok {
		name := p.Executable
		if name == "" {
			name = p.Name
		}
		return fmt.Sprintf("%s (pid %d)", name, p.PID)
	}
	if label := v.labels[f.Subject]; label != "" {
		return label
	}
	return f.Subject
}

// why states the observed facts that make the finding apply.
func (v view) why(f domain.Finding) string {
	if file, ok := v.files[f.Subject]; ok {
		perm := fs.FileMode(file.Mode & 0o777)
		parts := []string{fmt.Sprintf("mode %04o (%s), owner uid %d, group gid %d", file.Mode&0o7777, perm.String()[1:], file.UID, file.GID)}
		var writers []string
		if file.Mode&0o002 != 0 {
			writers = append(writers, "any local user")
		}
		if file.Mode&0o020 != 0 && file.GID != 0 {
			writers = append(writers, fmt.Sprintf("members of group %d", file.GID))
		}
		if len(writers) > 0 {
			parts = append(parts, "writable by "+strings.Join(writers, " and "))
		}
		if file.Mode&0o4000 != 0 {
			parts = append(parts, "set-user-ID")
		}
		if file.ReadOnly == domain.Observed {
			parts = append(parts, "on a read-only mount")
		}
		return strings.Join(parts, "; ")
	}
	if p, ok := v.process[f.Subject]; ok {
		parts := []string{fmt.Sprintf("effective uid %d", p.Identity.UID[1])}
		if listeners := v.sockets[p.ID]; len(listeners) > 0 {
			shown := listeners[:min(3, len(listeners))]
			text := "listens on " + strings.Join(shown, ", ")
			if len(listeners) > len(shown) {
				text += fmt.Sprintf(" and %d more", len(listeners)-len(shown))
			}
			parts = append(parts, text)
		}
		if p.Seccomp == 0 {
			parts = append(parts, "no seccomp filter")
		}
		if p.NoNewPrivs == 0 {
			parts = append(parts, "NoNewPrivs off")
		}
		return strings.Join(parts, "; ")
	}
	return ""
}

// suggestion is a reviewable command for permission findings. It is advice:
// LASA never runs it. Paths that need escaping to display are not offered.
func (v view) suggestion(f domain.Finding) string {
	file, ok := v.files[f.Subject]
	if !ok || file.Mode&0o022 == 0 || Safe(file.Path) != file.Path {
		return ""
	}
	quoted := shellQuote(file.Path)
	cmd := "sudo chmod go-w -- " + quoted
	if file.Kind == "sudoers" {
		cmd += " && sudo visudo -cf " + quoted
	}
	return cmd
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// exposure renders the exposure dimension; it does not apply to files.
func (v view) exposure(f domain.Finding) string {
	if v.kinds[f.Subject] == "file" {
		return "n/a"
	}
	return string(f.Exposure)
}

// ShortIDs returns, for each finding ID, the shortest prefix of at least
// eight characters that is unique among the given findings.
func ShortIDs(findings []domain.Finding) map[string]string {
	out := map[string]string{}
	for n := 8; n <= 32; n += 4 {
		counts := map[string]int{}
		for _, f := range findings {
			counts[f.ID[:min(n, len(f.ID))]]++
		}
		done := true
		for _, f := range findings {
			if _, ok := out[f.ID]; ok {
				continue
			}
			p := f.ID[:min(n, len(f.ID))]
			if counts[p] == 1 || n >= len(f.ID) {
				out[f.ID] = p
			} else {
				done = false
			}
		}
		if done {
			break
		}
	}
	return out
}

// commonWarnings are caveats present on every finding; they are printed once.
func commonWarnings(findings []domain.Finding) map[string]bool {
	if len(findings) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, f := range findings {
		seen := map[string]bool{}
		for _, w := range f.Warnings {
			if !seen[w] {
				counts[w]++
				seen[w] = true
			}
		}
	}
	out := map[string]bool{}
	for w, n := range counts {
		if n == len(findings) {
			out[w] = true
		}
	}
	return out
}

// diagnosticGroup summarizes diagnostics with the same code and component.
type diagnosticGroup struct {
	Code, Component, Summary, Action string
	Expected                         bool
	Count                            int
	Examples                         []string
}

var codeSummaries = map[string]string{
	diagnostics.CodeSymlinkNotFollowed: "symbolic links not followed (by design)",
	diagnostics.CodeNotPresent:         "configured paths do not exist",
	diagnostics.CodeNotSupported:       "controls not provided by this kernel",
	"PERMISSION_DENIED":                "unreadable (permission denied)",
	"NOT_FOUND":                        "not found",
	"UNSAFE_PATH":                      "paths through symbolic links",
	"RESOURCE_LIMIT":                   "resource budget reached",
	"SCAN_CANCELLED":                   "cancelled or timed out",
}

func groupDiagnostics(ds []domain.Diagnostic) []diagnosticGroup {
	index := map[string]int{}
	var groups []diagnosticGroup
	for _, d := range ds {
		key := d.Code + "\x00" + d.Component
		i, ok := index[key]
		if !ok {
			summary := codeSummaries[d.Code]
			if summary == "" {
				summary = strings.ToLower(strings.ReplaceAll(d.Code, "_", " "))
			}
			i = len(groups)
			index[key] = i
			groups = append(groups, diagnosticGroup{Code: d.Code, Component: d.Component, Summary: summary, Action: d.Remediation, Expected: diagnostics.IsExpected(d.Code)})
		}
		groups[i].Count++
		if len(groups[i].Examples) < 3 {
			groups[i].Examples = append(groups[i].Examples, d.Target)
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Component != groups[j].Component {
			return groups[i].Component < groups[j].Component
		}
		return groups[i].Count > groups[j].Count
	})
	return groups
}
