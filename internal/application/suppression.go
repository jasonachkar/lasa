package application

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

type Suppression struct {
	Fingerprint   string     `json:"fingerprint"`
	Justification string     `json:"justification"`
	Expires       *time.Time `json:"expires,omitempty"`
}
type Policy struct {
	Schema  string        `json:"schema"`
	Entries []Suppression `json:"entries"`
}

func ParsePolicy(raw []byte) (Policy, error) {
	var p Policy
	if len(raw) > 1<<20 {
		return p, fmt.Errorf("suppression policy exceeds 1MiB")
	}
	if e := jsonv2.Unmarshal(raw, &p, jsonv2.RejectUnknownMembers(true)); e != nil {
		return p, fmt.Errorf("invalid suppression policy: %w", e)
	}
	if p.Schema != "lasa.suppressions/v1" || len(p.Entries) > 4096 {
		return p, fmt.Errorf("unsupported suppression schema or too many entries")
	}
	seen := map[string]bool{}
	for _, x := range p.Entries {
		if x.Fingerprint == "" || strings.TrimSpace(x.Justification) == "" || seen[x.Fingerprint] {
			return p, fmt.Errorf("suppression requires unique fingerprint and nonempty justification")
		}
		seen[x.Fingerprint] = true
	}
	return p, nil
}
func ApplyPolicy(s *domain.Snapshot, p Policy, now time.Time) {
	entries := map[string]Suppression{}
	for _, x := range p.Entries {
		if x.Expires == nil || now.Before(*x.Expires) {
			entries[x.Fingerprint] = x
		}
	}
	for i := range s.Findings {
		f := &s.Findings[i]
		if x, ok := entries[f.ID]; ok {
			f.Suppressed = true
			f.SuppressionReason = x.Justification
		}
	}
}
