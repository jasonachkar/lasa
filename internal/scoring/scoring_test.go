package scoring

import (
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestScore(t *testing.T) {
	a, f := Score("high", domain.Potential, true)
	sum := 0
	for _, x := range f {
		sum += x.Contribution
	}
	if a != 75 || a != sum {
		t.Fatalf("%d %+v", a, f)
	}
	b, _ := Score("high", domain.UnknownExposure, true)
	if b >= a {
		t.Fatal("exposure has no effect")
	}
}
