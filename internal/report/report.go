// Package report renders saved evidence without accessing the scanned system.
package report

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"html/template"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jasonachkar/lasa/internal/domain"
)

const MaxInput = 64 << 20

func Safe(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", s[0])
			s = s[1:]
			continue
		}
		s = s[size:]
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ErrExportLimit reports a JSON export that cannot be written or read back.
var ErrExportLimit = fmt.Errorf("report exceeds the %d MiB export limit even after reducing file scope; narrow --roots or lower --max-files/--max-processes", MaxInput>>20)

// Marshal produces the canonical JSON export: sorted, with empty collections
// encoded as [] or {} rather than null.
func Marshal(s domain.Snapshot) ([]byte, error) {
	s.Sort()
	domain.EmptyCollections(&s)
	return json.MarshalIndent(s, "", "  ")
}

func Render(s domain.Snapshot, format string) ([]byte, error) {
	s.Sort()
	domain.EmptyCollections(&s)
	switch format {
	case "json":
		raw, e := Marshal(s)
		if e == nil && len(raw) > MaxInput {
			return nil, ErrExportLimit
		}
		return raw, e
	case "terminal":
		return renderTerminal(s, TerminalOptions{}), nil
	case "html":
		return html(s)
	case "sarif":
		return sarif(s)
	default:
		return nil, fmt.Errorf("unsupported format %q; choose terminal, json, html or sarif", format)
	}
}
func Decode(raw []byte) (domain.Snapshot, error) {
	var s domain.Snapshot
	if len(raw) > MaxInput {
		return s, fmt.Errorf("report exceeds 64MiB")
	}
	if e := jsonv2.Unmarshal(raw, &s, jsonv2.RejectUnknownMembers(true)); e != nil {
		return s, fmt.Errorf("invalid report JSON: %w", e)
	}
	if s.Schema != domain.SchemaVersion || s.ScanID == "" || s.Host.ID == "" {
		return s, fmt.Errorf("report requires supported schema %s, scan_id and host.id", domain.SchemaVersion)
	}
	if len(s.Observations) > 200000 || len(s.Graph.Edges) > 200000 || len(s.Findings) > 65536 {
		return s, fmt.Errorf("report structural budget exceeded")
	}
	nodes := map[string]bool{}
	for _, n := range s.Graph.Nodes {
		if n.ID == "" || nodes[n.ID] {
			return s, fmt.Errorf("empty or duplicate graph node %q", n.ID)
		}
		nodes[n.ID] = true
	}
	if len(s.Processes) > 65536 || len(s.Sockets) > 65536 || len(s.Mounts) > 32768 || len(s.Files) > 100000 || len(s.Evaluations) > 2000000 {
		return s, fmt.Errorf("report entity budget exceeded")
	}
	for _, c := range s.Coverage {
		if s.Complete && !c.Complete {
			return s, fmt.Errorf("complete snapshot has incomplete collector coverage")
		}
	}
	ids := map[string]bool{}
	for _, o := range s.Observations {
		if o.ID == "" || ids[o.ID] {
			return s, fmt.Errorf("missing or duplicate observation ID %q", o.ID)
		}
		ids[o.ID] = true
		switch o.State {
		case domain.Observed, domain.NotObserved, domain.Unknown, domain.NotApplicable:
		default:
			return s, fmt.Errorf("invalid observation state %q", o.State)
		}
	}
	for _, o := range s.Observations {
		for _, id := range o.Evidence {
			if !ids[id] {
				return s, fmt.Errorf("observation %s references missing evidence %s", o.ID, id)
			}
		}
	}
	findingIDs := map[string]bool{}
	for _, f := range s.Findings {
		if f.ID == "" || findingIDs[f.ID] || !nodes[f.Subject] {
			return s, fmt.Errorf("invalid, duplicate, or missing-subject finding %q", f.ID)
		}
		findingIDs[f.ID] = true
		if f.Priority < 0 || f.Priority > 100 {
			return s, fmt.Errorf("invalid priority in finding %s", f.ID)
		}
		switch f.Severity {
		case "critical", "high", "medium", "low", "informational":
		default:
			return s, fmt.Errorf("invalid severity in finding %s", f.ID)
		}
		switch f.Confidence {
		case "confirmed", "high", "medium", "low", "unknown":
		default:
			return s, fmt.Errorf("invalid confidence in finding %s", f.ID)
		}
		switch f.Exposure {
		case domain.Confirmed, domain.Potential, domain.Local, domain.UnknownExposure:
		default:
			return s, fmt.Errorf("invalid exposure in finding %s", f.ID)
		}
		for _, subject := range f.Subjects {
			if !nodes[subject] {
				return s, fmt.Errorf("finding references unknown affected subject %s", subject)
			}
		}
		for _, id := range f.Path.Entities {
			if !nodes[id] {
				return s, fmt.Errorf("attack scenario references unknown entity %s", id)
			}
		}
		for _, id := range f.Evidence {
			if !ids[id] {
				return s, fmt.Errorf("finding %s references missing evidence %s", f.ID, id)
			}
		}
	}
	for _, e := range s.Graph.Edges {
		if !nodes[e.From] || !nodes[e.To] {
			return s, fmt.Errorf("graph edge references unknown endpoint")
		}
		if len(e.Evidence) == 0 {
			return s, fmt.Errorf("graph edge missing provenance")
		}
		for _, id := range e.Evidence {
			if !ids[id] {
				return s, fmt.Errorf("graph references missing evidence %s", id)
			}
		}
	}
	return s, nil
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{"safe": func(v any) string { return Safe(fmt.Sprint(v)) }}).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>LASA report</title><style>
:root{--bg:#f6f8fa;--card:#fff;--fg:#1b2533;--muted:#5b6778;--line:#d5dbe3;--critical:#8a1538;--high:#b42318;--medium:#a15c00;--low:#0b6e8a;--informational:#5b6778;--ok:#1a7f37}
@media(prefers-color-scheme:dark){:root{--bg:#0f141a;--card:#161d26;--fg:#e6edf3;--muted:#9aa7b5;--line:#2b3542;--critical:#ff7b9c;--high:#ff7b72;--medium:#e3b341;--low:#56d4f5;--informational:#9aa7b5;--ok:#56d364}}
body{font:15px/1.55 system-ui,sans-serif;max-width:78rem;margin:auto;padding:1rem;color:var(--fg);background:var(--bg)}
section,article{background:var(--card);border:1px solid var(--line);border-radius:.6rem;padding:1rem 1.2rem;margin:1rem 0}
article{border-left:.35rem solid var(--sev)}h1{margin:.2rem 0}h2{margin-top:0}h3{margin:.1rem 0 .5rem}
code{overflow-wrap:anywhere;font-size:.9em}.muted{color:var(--muted)}table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
.sev{font-weight:700;color:var(--sev);text-transform:uppercase;white-space:nowrap}
.pill{display:inline-block;padding:.1rem .6rem;border-radius:1rem;border:1px solid var(--sev);color:var(--sev);margin-right:.4rem;font-weight:600}
dl{display:grid;grid-template-columns:9rem 1fr;gap:.25rem 1rem;margin:0}dt{color:var(--muted)}dd{margin:0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);padding:.5rem;border-radius:.4rem;margin:0}
.critical{--sev:var(--critical)}.high{--sev:var(--high)}.medium{--sev:var(--medium)}.low{--sev:var(--low)}.informational{--sev:var(--informational)}
@media(max-width:40rem){table{display:block;overflow:auto}dl{grid-template-columns:1fr}}
</style></head><body><header><h1>LASA evidence report</h1>
<p class="muted">LASA {{safe .Version}} · {{safe .S.Profile}} profile · scan <code>{{safe .S.ScanID}}</code> · {{safe .S.Started}}</p>
<p>Scope: {{safe .S.Host.Scope}}<br>{{len .S.Processes}} processes · {{len .S.Sockets}} sockets · {{len .S.Files}} files · coverage <strong>{{if .S.Complete}}complete{{else}}partial{{end}}</strong> within the declared scope.</p>
<p>{{range .Counts}}<span class="pill {{.Severity}}">{{.Count}} {{.Severity}}</span>{{else}}<strong>No findings.</strong> {{if not .S.Complete}}Coverage is partial, so this is not a clean bill of health.{{end}}{{end}}</p>
<p class="muted">Findings are conditional and are not proof of exploitation. Report data is sensitive.</p></header><main>
{{if .Findings}}<section><h2>Findings</h2><table><thead><tr><th>ID</th><th>Severity</th><th>Priority</th><th>Finding</th><th>Affected</th></tr></thead><tbody>{{range .Findings}}<tr class="{{.Finding.Severity}}"><td><a href="#{{safe .Finding.ID}}"><code>{{safe .Short}}</code></a></td><td class="sev">{{safe .Finding.Severity}}</td><td>{{.Finding.Priority}}</td><td>{{safe .Finding.Title}}{{if .Finding.Suppressed}} <em>(suppressed)</em>{{end}}</td><td><code>{{safe .Subject}}</code></td></tr>{{end}}</tbody></table></section>
{{range .Findings}}<article id="{{safe .Finding.ID}}" class="{{.Finding.Severity}}"><p class="sev">{{safe .Finding.Severity}} · priority {{.Finding.Priority}}</p><h3>{{safe .Finding.Title}}</h3><dl>
<dt>Affected</dt><dd><code>{{safe .Subject}}</code></dd>
{{if .Why}}<dt>Why</dt><dd>{{safe .Why}}</dd>{{end}}
{{if .Finding.Suppressed}}<dt>Status</dt><dd>Suppressed: {{safe .Finding.SuppressionReason}}</dd>{{end}}
<dt>Risk</dt><dd>{{safe .Finding.Path.ConditionalStep}}</dd>
{{if .Impact}}<dt>Impact</dt><dd>{{safe .Impact}}</dd>{{end}}
<dt>Requires</dt><dd>{{range .Finding.Prerequisites}}{{safe .}} {{end}}</dd>
<dt>Fix</dt><dd>{{safe .Finding.Remediation}}</dd>
{{if .Suggestion}}<dt>Suggested</dt><dd><pre>{{safe .Suggestion}}</pre><span class="muted">Review before running; LASA never runs commands.</span></dd>{{end}}
<dt>Assessment</dt><dd>confidence {{safe .Finding.Confidence}} · exposure {{safe .Exposure}} · rule {{safe .Finding.RuleID}} v{{safe .Finding.RuleVersion}}</dd>
<dt>Fingerprint</dt><dd><code>{{safe .Finding.ID}}</code></dd>
{{range .Caveats}}<dt>Caveat</dt><dd>{{safe .}}</dd>{{end}}</dl>
<details><summary>Evidence ({{len .Evidence}} observations)</summary><table><thead><tr><th>Fact</th><th>Value</th><th>State</th><th>Source</th></tr></thead><tbody>{{range .Evidence}}<tr><td>{{safe .Key}}</td><td><code>{{safe .Value}}</code></td><td>{{safe .State}}</td><td><code>{{safe .Source}}</code></td></tr>{{end}}</tbody></table></details></article>{{end}}{{end}}
{{if .Notes}}<section><h2>Notes</h2><ul>{{range .Notes}}<li>{{safe .}}</li>{{end}}</ul></section>{{end}}
<section><h2>Coverage</h2><table><thead><tr><th>Collector</th><th>Status</th><th>Attempted</th><th>Successful</th><th>Skipped</th><th>Not applicable</th><th>Inconclusive</th></tr></thead><tbody>{{range .S.Coverage}}<tr><th>{{safe .Collector}}</th><td>{{if .Complete}}complete{{else}}partial{{end}}</td><td>{{.Attempted}}</td><td>{{.Successful}}</td><td>{{.Skipped}}</td><td>{{.Unsupported}}</td><td>{{.Inconclusive}}</td></tr>{{end}}</tbody></table></section>
{{if .Gaps}}<section><h2>Collection gaps</h2><p class="muted">Checks LASA could not complete. Unknown never counts as secure.</p><table><thead><tr><th>Collector</th><th>Gap</th><th>Examples</th><th>Action</th></tr></thead><tbody>{{range .Gaps}}<tr><td>{{safe .Component}}</td><td>{{.Count}} {{safe .Summary}}</td><td>{{range .Examples}}<code>{{safe .}}</code><br>{{end}}</td><td>{{safe .Action}}</td></tr>{{end}}</tbody></table></section>{{end}}
{{if .Expected}}<section><h2>Not inspected by design</h2><table><tbody>{{range .Expected}}<tr><td>{{safe .Component}}</td><td>{{.Count}} {{safe .Summary}}</td><td>{{range .Examples}}<code>{{safe .}}</code><br>{{end}}</td></tr>{{end}}</tbody></table></section>{{end}}
<section><details><summary>All diagnostics ({{len .S.Diagnostics}})</summary><table><thead><tr><th>Code</th><th>Target</th><th>Cause</th><th>Action</th></tr></thead><tbody>{{range .S.Diagnostics}}<tr><td>{{safe .Code}}</td><td><code>{{safe .Target}}</code></td><td>{{safe .Cause}}</td><td>{{safe .Remediation}}</td></tr>{{end}}</tbody></table></details></section>
<section><details><summary>All recorded evidence ({{len .S.Observations}} observations)</summary><table><thead><tr><th>ID</th><th>Fact</th><th>Value</th><th>State / source</th></tr></thead><tbody>{{range .S.Observations}}<tr><td><code>{{safe .ID}}</code></td><td>{{safe .Key}}</td><td>{{safe .Value}}</td><td>{{safe .State}} / {{safe .Source}}</td></tr>{{end}}</tbody></table></details></section>
</main></body></html>`))

type htmlFinding struct {
	Finding                                   domain.Finding
	Short, Subject, Why, Suggestion, Exposure string
	Impact                                    string
	Caveats                                   []string
	Evidence                                  []domain.Observation
}

type severityCount struct {
	Severity string
	Count    int
}

func html(s domain.Snapshot) ([]byte, error) {
	v := newView(s)
	ids := ShortIDs(s.Findings)
	common := commonWarnings(s.Findings)
	observations := make(map[string]domain.Observation, len(s.Observations))
	for _, o := range s.Observations {
		observations[o.ID] = o
	}
	data := struct {
		S              domain.Snapshot
		Version        string
		Findings       []htmlFinding
		Counts         []severityCount
		Gaps, Expected []diagnosticGroup
		Notes          []string
	}{S: s, Version: domain.Version}
	counts := map[string]int{}
	for _, f := range s.Findings {
		counts[f.Severity]++
		h := htmlFinding{Finding: f, Short: ids[f.ID], Subject: v.subject(f), Why: v.why(f), Suggestion: v.suggestion(f), Exposure: v.exposure(f)}
		if f.Path.PotentialImpact != f.Description && f.Path.PotentialImpact != f.Path.ConditionalStep {
			h.Impact = f.Path.PotentialImpact
		}
		for _, w := range f.Warnings {
			if !common[w] {
				h.Caveats = append(h.Caveats, w)
			}
		}
		for _, id := range f.Evidence {
			if o, ok := observations[id]; ok {
				h.Evidence = append(h.Evidence, o)
			}
		}
		data.Findings = append(data.Findings, h)
	}
	for _, sev := range severityOrder {
		if counts[sev] > 0 {
			data.Counts = append(data.Counts, severityCount{sev, counts[sev]})
		}
	}
	for _, g := range groupDiagnostics(s.Diagnostics) {
		if g.Expected {
			data.Expected = append(data.Expected, g)
		} else {
			data.Gaps = append(data.Gaps, g)
		}
	}
	for _, f := range s.Findings {
		for _, w := range f.Warnings {
			if common[w] {
				data.Notes = append(data.Notes, w)
				delete(common, w)
			}
		}
	}
	var b bytes.Buffer
	e := htmlTemplate.Execute(&b, data)
	return b.Bytes(), e
}
func sarif(s domain.Snapshot) ([]byte, error) {
	v := newView(s)
	byRule := map[string]domain.Finding{}
	for _, f := range s.Findings {
		if _, ok := byRule[f.RuleID]; !ok {
			byRule[f.RuleID] = f
		}
	}
	keys := make([]string, 0, len(byRule))
	for id := range byRule {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	descriptors := []any{}
	for _, id := range keys {
		f := byRule[id]
		descriptors = append(descriptors, map[string]any{"id": id, "name": id, "shortDescription": map[string]string{"text": f.Title}, "fullDescription": map[string]string{"text": f.Description}, "help": map[string]string{"text": f.Remediation}, "properties": map[string]any{"security-severity-label": f.Severity}})
	}
	results := []any{}
	for _, f := range s.Findings {
		level := "warning"
		if f.Severity == "critical" || f.Severity == "high" {
			level = "error"
		} else if f.Severity == "low" || f.Severity == "informational" {
			level = "note"
		}
		subject := v.subject(f)
		text := f.Title + ": " + subject + "."
		if why := v.why(f); why != "" {
			text += " " + why + "."
		}
		text += " " + f.Path.ConditionalStep + " Remediation: " + f.Remediation
		kind := v.kinds[f.Subject]
		if kind == "" {
			kind = "resource"
		}
		location := map[string]any{"logicalLocations": []any{map[string]string{"name": subject, "fullyQualifiedName": kind + ":" + subject, "kind": "resource"}}}
		properties := map[string]any{"confidence": f.Confidence, "exposure": f.Exposure, "priority": f.Priority, "evidence": f.Evidence, "warnings": f.Warnings, "subject_id": f.Subject, "stable_subject": f.StableSubject, "host_id": s.Host.ID}
		if file, ok := v.files[f.Subject]; ok {
			// A host file is a real artifact location, not a fabricated
			// source-code position.
			location["physicalLocation"] = map[string]any{"artifactLocation": map[string]string{"uri": (&url.URL{Scheme: "file", Path: file.Path}).String()}}
			properties["mode"] = fmt.Sprintf("%04o", file.Mode&0o7777)
			properties["uid"] = file.UID
			properties["gid"] = file.GID
		}
		r := map[string]any{"ruleId": f.RuleID, "level": level, "message": map[string]string{"text": text}, "partialFingerprints": map[string]string{"lasa/v1": f.ID}, "locations": []any{location}, "properties": properties}
		if f.Suppressed {
			r["suppressions"] = []any{map[string]string{"kind": "external", "justification": f.SuppressionReason, "status": "accepted"}}
		}
		results = append(results, r)
	}
	return json.MarshalIndent(map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "LASA", "version": domain.Version, "informationUri": "https://github.com/jasonachkar/lasa", "rules": descriptors}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": true, "properties": map[string]any{"collectionComplete": s.Complete}}}}}}, "", "  ")
}
