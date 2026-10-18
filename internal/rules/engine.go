// Package rules implements a closed typed predicate language with explicit uncertainty.
package rules

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/jasonachkar/lasa/internal/domain"
	"gopkg.in/yaml.v3"
)

const Schema = "lasa.rules/v1"

type Condition struct {
	All       []Condition `yaml:"all,omitempty" json:"all,omitempty"`
	Any       []Condition `yaml:"any,omitempty" json:"any,omitempty"`
	Not       *Condition  `yaml:"not,omitempty" json:"not,omitempty"`
	Predicate string      `yaml:"predicate,omitempty" json:"predicate,omitempty"`
	Op        string      `yaml:"op,omitempty" json:"op,omitempty"`
	Value     any         `yaml:"value,omitempty" json:"value,omitempty"`
}
type Rule struct {
	ID               string    `yaml:"id" json:"id"`
	Version          string    `yaml:"version" json:"version"`
	Category         string    `yaml:"category" json:"category"`
	Subject          string    `yaml:"subject" json:"subject"`
	Title            string    `yaml:"title" json:"title"`
	Description      string    `yaml:"description" json:"description"`
	Severity         string    `yaml:"severity" json:"severity"`
	Confidence       string    `yaml:"confidence" json:"confidence"`
	Unknown          string    `yaml:"unknown" json:"unknown"`
	RequiredEvidence []string  `yaml:"required_evidence" json:"required_evidence"`
	Prerequisites    []string  `yaml:"prerequisites" json:"prerequisites"`
	Remediation      string    `yaml:"remediation" json:"remediation"`
	When             Condition `yaml:"when" json:"when"`
}
type Pack struct {
	Schema string `yaml:"schema" json:"schema"`
	Rules  []Rule `yaml:"rules" json:"rules"`
}

var registry = map[string]string{"network.potential": "bool", "network.confirmed": "bool", "network.management": "bool", "privilege.host_root": "bool", "capability.dangerous": "bool", "isolation.weak": "bool", "container.hint": "bool", "container.host_pid": "bool", "container.sensitive_mount": "bool", "file.owner_root": "bool", "file.suid": "bool", "file.capability": "bool", "file.write_candidate": "bool", "file.unsafe_parent": "bool", "file.privileged_execution": "bool", "file.acl_present": "bool", "file.readonly": "bool", "file.search_path": "bool", "file.kind": "string", "identity.euid": "number"}

func Load(r io.Reader) ([]Rule, error) {
	raw, e := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("rule pack exceeds 1MiB")
	}
	var node yaml.Node
	if e = yaml.Unmarshal(raw, &node); e != nil {
		return nil, fmt.Errorf("rule YAML: %w", e)
	}
	nodes := 0
	var walk func(*yaml.Node, int) error
	walk = func(n *yaml.Node, depth int) error {
		nodes++
		if n.Kind != yaml.DocumentNode {
			switch n.Tag {
			case "!!map", "!!seq", "!!str", "!!bool", "!!int", "!!float", "!!null":
			default:
				return fmt.Errorf("unsupported YAML tag %q", n.Tag)
			}
		}
		if n.Kind == yaml.AliasNode || n.Anchor != "" {
			return fmt.Errorf("YAML aliases and anchors are prohibited")
		}
		if depth > 32 || nodes > 16384 {
			return fmt.Errorf("YAML structural budget exceeded")
		}
		for _, child := range n.Content {
			if e := walk(child, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	if e = walk(&node, 0); e != nil {
		return nil, e
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var p Pack
	if e = dec.Decode(&p); e != nil {
		return nil, fmt.Errorf("rule pack: %w", e)
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		return nil, fmt.Errorf("exactly one YAML document is required")
	}
	if p.Schema != Schema {
		return nil, fmt.Errorf("unsupported rules schema %q", p.Schema)
	}
	if len(p.Rules) > 256 {
		return nil, fmt.Errorf("at most 256 rules are allowed")
	}
	ids := map[string]bool{}
	for _, r := range p.Rules {
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate rule ID %s", r.ID)
		}
		ids[r.ID] = true
		if e = r.Validate(); e != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, e)
		}
	}
	sort.Slice(p.Rules, func(i, j int) bool { return p.Rules[i].ID < p.Rules[j].ID })
	return p.Rules, nil
}
func (r Rule) Validate() error {
	if r.ID == "" || len(r.ID) > 128 || r.Version != "1" || r.Category == "" || r.Title == "" || r.Description == "" || r.Remediation == "" || len(r.Prerequisites) == 0 || len(r.RequiredEvidence) == 0 {
		return fmt.Errorf("required metadata missing or unsupported rule version (require 1)")
	}
	if r.Subject != "process" && r.Subject != "file" {
		return fmt.Errorf("subject must be process or file")
	}
	if SeverityRank(r.Severity) < 0 {
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Confidence != "high" && r.Confidence != "medium" && r.Confidence != "low" {
		return fmt.Errorf("confidence must be high, medium or low")
	}
	if r.Unknown != "skip" {
		return fmt.Errorf("unknown behavior must be skip; unknown never becomes a finding")
	}
	for _, k := range r.RequiredEvidence {
		if _, ok := registry[k]; !ok {
			return fmt.Errorf("unknown required evidence %s", k)
		}
	}
	count := 0
	return validate(r.When, 0, &count)
}
func validate(c Condition, depth int, count *int) error {
	*count++
	if depth > 16 || *count > 256 {
		return fmt.Errorf("condition budget exceeded")
	}
	n := 0
	if len(c.All) > 0 {
		n++
	}
	if len(c.Any) > 0 {
		n++
	}
	if c.Not != nil {
		n++
	}
	if c.Predicate != "" {
		n++
	}
	if n != 1 {
		return fmt.Errorf("exactly one of all, any, not, predicate required")
	}
	if c.Predicate == "" && (c.Op != "" || c.Value != nil) {
		return fmt.Errorf("composition cannot have op/value")
	}
	for _, list := range [][]Condition{c.All, c.Any} {
		for _, x := range list {
			if e := validate(x, depth+1, count); e != nil {
				return e
			}
		}
	}
	if c.Not != nil {
		return validate(*c.Not, depth+1, count)
	}
	if c.Predicate == "" {
		return nil
	}
	typ, ok := registry[c.Predicate]
	if !ok {
		return fmt.Errorf("unknown predicate %s", c.Predicate)
	}
	switch typ {
	case "bool":
		if _, ok := c.Value.(bool); !ok {
			return fmt.Errorf("%s requires boolean value", c.Predicate)
		}
		if c.Op != "eq" && c.Op != "neq" {
			return fmt.Errorf("boolean operator must be eq/neq")
		}
	case "string":
		if _, ok := c.Value.(string); !ok {
			return fmt.Errorf("%s requires string value", c.Predicate)
		}
		if c.Op != "eq" && c.Op != "neq" {
			return fmt.Errorf("string operator must be eq/neq")
		}
	case "number":
		switch c.Value.(type) {
		case int, uint64, float64:
		default:
			return fmt.Errorf("%s requires numeric value", c.Predicate)
		}
		switch c.Op {
		case "eq", "neq", "gt", "lt":
		default:
			return fmt.Errorf("numeric operator must be eq/neq/gt/lt")
		}
	}
	return nil
}
func SeverityRank(s string) int {
	switch s {
	case "informational":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return -1
}

type EvidenceIndex map[string]map[string][]domain.Observation

func Index(obs []domain.Observation) EvidenceIndex {
	out := EvidenceIndex{}
	for _, o := range obs {
		if out[o.Subject] == nil {
			out[o.Subject] = map[string][]domain.Observation{}
		}
		out[o.Subject][o.Key] = append(out[o.Subject][o.Key], o)
	}
	return out
}

type Result struct {
	State    domain.State
	Evidence []string
	Reason   string
}

func Evaluate(c Condition, subject string, idx EvidenceIndex) Result {
	if c.Not != nil {
		r := Evaluate(*c.Not, subject, idx)
		if r.State == domain.Observed {
			r.State = domain.NotObserved
		} else if r.State == domain.NotObserved {
			r.State = domain.Observed
		}
		return r
	}
	list := c.All
	all := len(list) > 0
	if !all {
		list = c.Any
	}
	if len(list) > 0 {
		var refs []string
		unknown, na := false, false
		for _, child := range list {
			r := Evaluate(child, subject, idx)
			refs = append(refs, r.Evidence...)
			if all && r.State == domain.NotObserved || !all && r.State == domain.Observed {
				return Result{r.State, unique(refs), r.Reason}
			}
			unknown = unknown || r.State == domain.Unknown
			na = na || r.State == domain.NotApplicable
		}
		if unknown {
			return Result{domain.Unknown, unique(refs), "required evidence is unavailable or conflicting"}
		}
		if na {
			return Result{domain.NotApplicable, unique(refs), "condition is not applicable"}
		}
		if all {
			return Result{domain.Observed, unique(refs), "all prerequisites observed"}
		}
		return Result{domain.NotObserved, unique(refs), "no alternative matched"}
	}
	obs := idx[subject][c.Predicate]
	if len(obs) == 0 {
		return Result{State: domain.Unknown, Reason: "missing " + c.Predicate}
	}
	var refs []string
	value := ""
	have := false
	for _, o := range obs {
		refs = append(refs, o.ID)
		refs = append(refs, o.Evidence...)
		if o.State != domain.Observed {
			return Result{o.State, unique(refs), "unavailable " + c.Predicate}
		}
		if have && o.Value != value {
			return Result{domain.Unknown, unique(refs), "conflicting " + c.Predicate}
		}
		value = o.Value
		have = true
	}
	matched := false
	switch registry[c.Predicate] {
	case "bool":
		actual, e := strconv.ParseBool(value)
		if e != nil {
			return Result{domain.Unknown, unique(refs), "invalid boolean observation"}
		}
		expected, ok := c.Value.(bool)
		if !ok {
			return Result{State: domain.Unknown, Reason: "invalid predicate type"}
		}
		matched = actual == expected
	case "string":
		matched = value == fmt.Sprint(c.Value)
	case "number":
		a, e := strconv.ParseFloat(value, 64)
		if e != nil {
			return Result{State: domain.Unknown, Reason: "invalid numeric observation"}
		}
		b, e := strconv.ParseFloat(fmt.Sprint(c.Value), 64)
		if e != nil {
			return Result{State: domain.Unknown, Reason: "invalid numeric operand"}
		}
		switch c.Op {
		case "gt":
			matched = a > b
		case "lt":
			matched = a < b
		default:
			matched = a == b
		}
	default:
		return Result{State: domain.Unknown, Reason: "unregistered predicate"}
	}
	if c.Op == "neq" {
		matched = !matched
	}
	state := domain.NotObserved
	if matched {
		state = domain.Observed
	}
	return Result{state, unique(refs), c.Predicate + " " + c.Op + " " + fmt.Sprint(c.Value)}
}
func unique(ids []string) []string {
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		if id != "" && (len(out) == 0 || out[len(out)-1] != id) {
			out = append(out, id)
		}
	}
	return out
}
func RequirementsSatisfied(r Rule, subject string, idx EvidenceIndex) bool {
	for _, key := range r.RequiredEvidence {
		obs := idx[subject][key]
		if len(obs) == 0 {
			return false
		}
		first := obs[0].Value
		for _, o := range obs {
			if o.State != domain.Observed || o.Value != first {
				return false
			}
		}
	}
	return true
}
