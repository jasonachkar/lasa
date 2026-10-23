// Package report renders saved evidence without accessing the scanned system.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
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
func Render(s domain.Snapshot, format string) ([]byte, error) {
	s.Sort()
	switch format {
	case "json":
		raw, e := json.MarshalIndent(s, "", "  ")
		if e == nil && len(raw) > MaxInput {
			return nil, fmt.Errorf("report exceeds 64MiB export limit; narrow roots or lower collection budgets")
		}
		return raw, e
	case "terminal":
		return terminal(s), nil
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
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&s); e != nil {
		return s, fmt.Errorf("invalid report JSON: %w", e)
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return s, fmt.Errorf("trailing report data")
	}
	if (s.Schema != domain.SchemaVersion && s.Schema != domain.LegacySchemaVersion) || s.ScanID == "" || s.Host.ID == "" {
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
	if s.Schema == domain.LegacySchemaVersion && (len(s.Assets) > 0 || len(s.Inspections) > 0 || len(s.RequestedRoots) > 0 || s.ScopeFingerprint != "") {
		return s, fmt.Errorf("inspection extensions require lasa.report/v2")
	}
	assets := map[string]bool{}
	for _, a := range s.Assets {
		if a.ID == "" || a.StableID == "" || a.Kind == "" || assets[a.ID] || !nodes[a.ID] {
			return s, fmt.Errorf("invalid or duplicate inspection asset %q", a.ID)
		}
		assets[a.ID] = true
	}
	if len(s.Assets) > 65536 {
		return s, fmt.Errorf("inspection asset budget exceeded")
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
func terminal(s domain.Snapshot) []byte {
	version := s.ScannerVersion
	if version == "" {
		version = "unknown"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "LASA %s | scan %s | profile %s\nScope: %s\nObserved: %d processes, %d sockets, %d files; findings: %d\nCollection complete within declared scope: %t\n", Safe(version), Safe(s.ScanID), Safe(s.Profile), Safe(s.Host.Scope), len(s.Processes), len(s.Sockets), len(s.Files), len(s.Findings), s.Complete)
	for _, f := range s.Findings {
		fmt.Fprintf(&b, "\n[%s] %s (%s) priority=%d confidence=%s exposure=%s suppressed=%t\n  %s\n  Evidence: %s\n  Conditional path: %s\n  Action: %s\n", Safe(f.Severity), Safe(f.RuleID), Safe(f.ID), f.Priority, Safe(f.Confidence), Safe(string(f.Exposure)), f.Suppressed, Safe(f.Title+". "+f.Description), Safe(strings.Join(f.Evidence, ", ")), Safe(f.Path.ConditionalStep), Safe(f.Remediation))
		for _, w := range f.Warnings {
			fmt.Fprintf(&b, "  Uncertainty: %s\n", Safe(w))
		}
	}
	fmt.Fprintln(&b, "\nCoverage (enumerated checks only; not a percentage of host security):")
	for _, c := range s.Coverage {
		fmt.Fprintf(&b, "  %s: attempted=%d successful=%d skipped=%d unsupported=%d inconclusive=%d complete=%t\n", Safe(c.Collector), c.Attempted, c.Successful, c.Skipped, c.Unsupported, c.Inconclusive, c.Complete)
	}
	if len(s.Diagnostics) > 0 {
		fmt.Fprintf(&b, "\nDiagnostics: %d (use JSON for every target/cause/action)\n", len(s.Diagnostics))
		limit := len(s.Diagnostics)
		if limit > 12 {
			limit = 12
		}
		for _, d := range s.Diagnostics[:limit] {
			fmt.Fprintf(&b, "  %s\n", Safe(d.Error()))
		}
	}
	return []byte(b.String())
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{"safe": func(v any) string { return Safe(fmt.Sprint(v)) }}).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>LASA report</title><style>body{font:1rem system-ui;line-height:1.6;max-width:80rem;margin:auto;padding:1rem;color:#182535;background:#f8fafc}article,section{background:white;border:1px solid #ccd3dd;border-radius:.5rem;padding:1rem;margin:1rem 0}code{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.5rem;border-bottom:1px solid #ccd3dd}.warning{color:#773600}@media(max-width:40rem){table{display:block;overflow:auto}}</style></head><body><header><h1>LASA evidence report</h1><p>Scanner {{safe .ScannerVersion}} · schema {{safe .Schema}}</p><p>Scan <code>{{safe .ScanID}}</code> · {{safe .Profile}} · {{safe .Started}}</p><p>Scope: {{safe .Host.Scope}}. Complete within declared scope: {{safe .Complete}}.</p><p>{{len .Processes}} processes · {{len .Sockets}} sockets · {{len .Files}} files · {{len .Findings}} findings.</p><p>Conditional scenarios are not proof of exploitation. Report data is sensitive.</p></header><main><section><h2>Findings</h2>{{range .Findings}}<article id="{{safe .ID}}"><h3>{{safe .Title}}</h3><p>{{safe .RuleID}} · {{safe .Severity}} · confidence {{safe .Confidence}} · exposure {{safe .Exposure}} · priority {{safe .Priority}} · suppressed {{safe .Suppressed}}</p><p>{{safe .Description}}</p><p>{{safe .Path.ConditionalStep}}</p><h4>Evidence references</h4>{{range .Evidence}}<code>{{safe .}}</code> {{end}}<h4>Uncertainty</h4><ul>{{range .Warnings}}<li class="warning">{{safe .}}</li>{{end}}</ul><h4>Remediation</h4><p>{{safe .Remediation}}</p></article>{{else}}<p>No findings established by the available evidence. This does not establish that the host is secure.</p>{{end}}</section><section><h2>Coverage</h2><table><thead><tr><th>Collector</th><th>Attempted</th><th>Successful</th><th>Skipped</th><th>Inconclusive</th><th>Complete</th></tr></thead><tbody>{{range .Coverage}}<tr><th>{{safe .Collector}}</th><td>{{safe .Attempted}}</td><td>{{safe .Successful}}</td><td>{{safe .Skipped}}</td><td>{{safe .Inconclusive}}</td><td>{{safe .Complete}}</td></tr>{{end}}</tbody></table></section><section><h2>Diagnostics</h2>{{range .Diagnostics}}<article><h3>{{safe .Code}}</h3><p>{{safe .Component}} / {{safe .Operation}} / <code>{{safe .Target}}</code></p><p>Cause: {{safe .Cause}}</p><p>Impact: {{safe .Impact}}</p><p>Action: {{safe .Remediation}}</p></article>{{else}}<p>No collection diagnostics.</p>{{end}}</section><section><h2>Evidence</h2><table><thead><tr><th>ID</th><th>Fact</th><th>Value</th><th>State / source</th></tr></thead><tbody>{{range .Observations}}<tr><td><code>{{safe .ID}}</code></td><td>{{safe .Key}}</td><td>{{safe .Value}}</td><td>{{safe .State}} / {{safe .Source}}</td></tr>{{end}}</tbody></table></section></main></body></html>`))

func html(s domain.Snapshot) ([]byte, error) {
	var b bytes.Buffer
	e := htmlTemplate.Execute(&b, s)
	return b.Bytes(), e
}
func sarif(s domain.Snapshot) ([]byte, error) {
	version := s.ScannerVersion
	if version == "" {
		version = "unknown"
	}
	ids := map[string]bool{}
	for _, f := range s.Findings {
		ids[f.RuleID] = true
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	descriptors := []any{}
	for _, id := range keys {
		descriptors = append(descriptors, map[string]any{"id": id, "shortDescription": map[string]string{"text": id}})
	}
	results := []any{}
	for _, f := range s.Findings {
		level := "warning"
		if f.Severity == "critical" || f.Severity == "high" {
			level = "error"
		} else if f.Severity == "low" || f.Severity == "informational" {
			level = "note"
		}
		r := map[string]any{"ruleId": f.RuleID, "level": level, "message": map[string]string{"text": f.Title + ". " + f.Description + " Remediation: " + f.Remediation}, "partialFingerprints": map[string]string{"lasa/v1": f.ID}, "locations": []any{map[string]any{"logicalLocations": []any{map[string]string{"name": f.Subject, "fullyQualifiedName": "lasa:" + s.Host.ID + ":" + f.StableSubject, "kind": "resource"}}}}, "properties": map[string]any{"confidence": f.Confidence, "exposure": f.Exposure, "priority": f.Priority, "evidence": f.Evidence, "warnings": f.Warnings}}
		if f.Suppressed {
			r["suppressions"] = []any{map[string]string{"kind": "external", "justification": f.SuppressionReason, "status": "accepted"}}
		}
		results = append(results, r)
	}
	return json.MarshalIndent(map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "LASA", "version": version, "informationUri": "https://github.com/jasonachkar/lasa", "rules": descriptors}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": true, "properties": map[string]any{"collectionComplete": s.Complete}}}}}}, "", "  ")
}
