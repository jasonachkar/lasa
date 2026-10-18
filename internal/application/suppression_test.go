package application

import (
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestSuppressionJustificationAndExpiry(t *testing.T) {
	for _, raw := range []string{`{"schema":"lasa.suppressions/v1","entries":[{"fingerprint":"x","justification":" "}]}`, `{"schema":"wrong","entries":[]}`, `{"schema":"lasa.suppressions/v1","entries":[]} {}`} {
		if _, e := ParsePolicy([]byte(raw)); e == nil {
			t.Fatal("invalid suppression policy accepted")
		}
	}
	p, e := ParsePolicy([]byte(`{"schema":"lasa.suppressions/v1","entries":[{"fingerprint":"x","justification":"reviewed","expires":"2026-12-01T00:00:00Z"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	for _, expired := range []bool{false, true} {
		s := domain.Snapshot{Findings: []domain.Finding{{ID: "x"}, {ID: "y"}}}
		now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		if expired {
			now = now.AddDate(0, 2, 0)
		}
		ApplyPolicy(&s, p, now)
		if s.Findings[0].Suppressed == expired || s.Findings[1].Suppressed {
			t.Fatalf("expiry/matching failed: %+v", s.Findings)
		}
	}
}
