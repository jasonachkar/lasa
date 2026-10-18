package scoring

import (
	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/rules"
)

const Version = "lasa.priority/v1"

func Score(severity string, exposure domain.Exposure, privileged bool) (int, []domain.Factor) {
	base := 10 + rules.SeverityRank(severity)*15
	f := []domain.Factor{{Name: "severity", Contribution: base, Reason: "rule consequence class"}}
	if exposure == domain.Potential {
		f = append(f, domain.Factor{Name: "potential_exposure", Contribution: 10, Reason: "non-loopback endpoint; upstream reachability unverified"})
	}
	if exposure == domain.Confirmed {
		f = append(f, domain.Factor{Name: "confirmed_exposure", Contribution: 20, Reason: "independent confirmed exposure observation"})
	}
	if privileged {
		f = append(f, domain.Factor{Name: "initial_namespace_privilege", Contribution: 10, Reason: "initial user namespace privilege observed"})
	}
	score := 0
	for _, x := range f {
		score += x.Contribution
	}
	if score > 100 {
		f = append(f, domain.Factor{Name: "cap", Contribution: 100 - score, Reason: "priority is bounded at 100"})
		score = 100
	}
	return score, f
}
