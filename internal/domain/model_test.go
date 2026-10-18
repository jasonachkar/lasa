package domain

import "testing"

func TestIdentityBoundaries(t *testing.T) {
	if Hash("ab", "c") == Hash("a", "bc") {
		t.Fatal("ambiguous hash framing")
	}
	a := Hash("boot", "pidns", "42", "1")
	b := Hash("boot", "pidns", "42", "2")
	if a == b {
		t.Fatal("PID reuse collision")
	}
}
