package rules

import (
	"bytes"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/rules/builtin"
)

func TestEveryBuiltin(t *testing.T) {
	pack, e := Load(bytes.NewReader(builtin.YAML))
	if e != nil {
		t.Fatal(e)
	}
	if len(pack) != 15 {
		t.Fatal("expected 15 reviewed rules")
	}
	cases := map[string]map[string]string{
		"LASA-001": {"network.potential": "true", "privilege.host_root": "true", "capability.dangerous": "true"},
		"LASA-002": {"network.confirmed": "true", "privilege.host_root": "true"},
		"LASA-003": {"network.potential": "true", "network.management": "true"},
		"LASA-004": {"privilege.host_root": "true", "isolation.weak": "true"},
		"LASA-005": {"container.hint": "true", "container.host_pid": "true"},
		"LASA-006": {"file.kind": "runtime_socket", "file.write_candidate": "true"},
		"LASA-007": {"file.privileged_execution": "true", "file.write_candidate": "true"},
		"LASA-008": {"file.kind": "service_config", "file.write_candidate": "true"},
		"LASA-009": {"file.kind": "sudoers", "file.write_candidate": "true"},
		"LASA-010": {"file.suid": "true", "file.write_candidate": "true", "file.unsafe_parent": "true"},
		"LASA-011": {"file.capability": "true", "file.write_candidate": "true", "file.unsafe_parent": "true"},
		"LASA-012": {"file.kind": "directory", "file.search_path": "true", "file.write_candidate": "true"},
		"LASA-013": {"file.kind": "authorized_keys", "file.write_candidate": "true"},
		"LASA-014": {"container.hint": "true", "container.sensitive_mount": "true"},
		"LASA-015": {"privilege.host_root": "true", "capability.dangerous": "true", "isolation.weak": "true"},
	}
	for _, r := range pack {
		t.Run(r.ID, func(t *testing.T) {
			vals := cases[r.ID]
			makeObs := func(negative bool, state domain.State) []domain.Observation {
				var out []domain.Observation
				for k, v := range vals {
					if negative {
						if v == "true" {
							v = "false"
						} else {
							v = "other"
						}
					}
					out = append(out, domain.Fact("subject", k, v, "fixture", "fixture", state, time.Unix(0, 0)))
				}
				return out
			}
			if result := Evaluate(r.When, "subject", Index(makeObs(false, domain.Observed))); result.State != domain.Observed {
				t.Fatalf("positive: %+v", result)
			}
			if result := Evaluate(r.When, "subject", Index(makeObs(true, domain.Observed))); result.State != domain.NotObserved {
				t.Fatalf("negative: %+v", result)
			}
			for _, state := range []domain.State{domain.Unknown, domain.NotApplicable} {
				if result := Evaluate(r.When, "subject", Index(makeObs(false, state))); result.State != state {
					t.Fatalf("%s: %+v", state, result)
				}
			}
			if result := Evaluate(r.When, "subject", Index(nil)); result.State != domain.Unknown {
				t.Fatalf("missing: %+v", result)
			}
			obs := append(makeObs(false, domain.Observed), makeObs(true, domain.Observed)...)
			if result := Evaluate(r.When, "subject", Index(obs)); result.State != domain.Unknown {
				t.Fatalf("conflict: %+v", result)
			}
		})
	}
}
