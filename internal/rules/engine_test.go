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
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		_, _ = Load(strings.NewReader(s))
	})
}
