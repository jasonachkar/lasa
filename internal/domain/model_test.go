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
func TestInvalidUTF8Identity(t *testing.T) {
	if Hash(string([]byte{0xff})) == Hash(string([]byte{0xfe})) {
		t.Fatal("distinct Linux byte names collapsed during identity framing")
	}
}
