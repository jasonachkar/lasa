package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestStrictLoad(t *testing.T) {
	for _, s := range []string{"schema: nope\nrules: []", "schema: lasa.rules/v1\nrules: []\nunexpected: true", "schema: lasa.rules/v1\nrules: &a [*a]", "schema: lasa.rules/v1\nrules:\n - id: X\n   version: '1'\n   when: {predicate: shell.execute, op: eq, value: true}"} {
		if _, e := Load(strings.NewReader(s)); e == nil {
			t.Fatalf("invalid YAML accepted: %s", s)
		}
	}
}
func TestThreeValuedLogic(t *testing.T) {
	c := Condition{All: []Condition{{Predicate: "network.potential", Op: "eq", Value: true}, {Predicate: "privilege.host_root", Op: "eq", Value: true}}}
	now := time.Now()
	fact := func(key, v string, state domain.State) domain.Observation {
		return domain.Fact("p", key, v, "fixture", "test", state, now)
	}
	idx := Index([]domain.Observation{fact("network.potential", "true", domain.Observed)})
	if r := Evaluate(c, "p", idx); r.State != domain.Unknown {
		t.Fatalf("missing => %s", r.State)
	}
	idx = Index([]domain.Observation{fact("network.potential", "true", domain.Observed), fact("privilege.host_root", "false", domain.Observed)})
	if r := Evaluate(c, "p", idx); r.State != domain.NotObserved {
		t.Fatal(r)
	}
	idx = Index([]domain.Observation{fact("network.potential", "true", domain.Observed), fact("network.potential", "false", domain.Observed), fact("privilege.host_root", "true", domain.Observed)})
	if r := Evaluate(c, "p", idx); r.State != domain.Unknown {
		t.Fatal("conflict not unknown", r)
	}
}
func FuzzLoad(f *testing.F) {
	f.Add("schema: lasa.rules/v1\nrules: []")
	f.Add(`{"schema":"lasa.rules/v1","rules":[{"id":"T","version":"1","category":"test","subject":"process","title":"test","description":"test","severity":"high","confidence":"medium","unknown":"skip","required_evidence":["identity.euid"],"prerequisites":["test"],"remediation":"test","when":{"predicate":"identity.euid","op":"eq","value":0}}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		_, _ = Load(strings.NewReader(s))
	})
}
func TestInvalidNumericEvidenceStaysUnknown(t *testing.T) {
	condition := Condition{Predicate: "identity.euid", Op: "neq", Value: 0}
	for _, value := range []string{"NaN", "+Inf", "-1", "1.5", "4294967296"} {
		o := domain.Fact("p", "identity.euid", value, "fixture", "fixture", domain.Observed, time.Unix(0, 0))
		if r := Evaluate(condition, "p", Index([]domain.Observation{o})); r.State != domain.Unknown {
			t.Fatalf("%s matched malformed numeric evidence: %+v", value, r)
		}
	}
}

func TestEveryRegisteredPredicateIsDocumented(t *testing.T) {
	if len(predicateDocs) != len(registry) {
		t.Fatalf("predicate docs (%d) and registry (%d) differ", len(predicateDocs), len(registry))
	}
	for _, p := range Predicates() {
		if p.Description == "" || (p.Subject != "process" && p.Subject != "file") {
			t.Errorf("predicate %s lacks a description or subject", p.Name)
		}
	}
}
