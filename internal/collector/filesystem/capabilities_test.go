package filesystem

import (
	"encoding/binary"
	"testing"
)

func TestFileCapabilities(t *testing.T) {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b, 0x02000001)
	if v, e := CapabilitiesEnabled(b); e != nil || v {
		t.Fatalf("empty cap set: %t %v", v, e)
	}
	b[4] = 2
	if v, e := CapabilitiesEnabled(b); e != nil || !v {
		t.Fatalf("cap set: %t %v", v, e)
	}
	if _, e := CapabilitiesEnabled(b[:12]); e == nil {
		t.Fatal("truncated cap accepted")
	}
	b[1] = 1
	if _, e := CapabilitiesEnabled(b); e == nil {
		t.Fatal("unknown flags accepted")
	}
}
