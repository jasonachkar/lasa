package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEventABI(t *testing.T) {
	raw := wire{Kind: 2, PID: 42, Family: 2, Port: 443, Address: [16]byte{127, 0, 0, 1}}
	var b bytes.Buffer
	if e := binary.Write(&b, binary.LittleEndian, raw); e != nil {
		t.Fatal(e)
	}
	if b.Len() != 88 {
		t.Fatal("ABI drift", b.Len())
	}
	e, err := decode(b.Bytes(), "boot")
	if err != nil || e.PID != 42 || e.Address != "127.0.0.1" || e.Kind != "connect_attempt" {
		t.Fatalf("%+v %v", e, err)
	}
	if _, e := decode(b.Bytes()[:80], "boot"); e == nil {
		t.Fatal("truncated event accepted")
	}
}
func TestEmbeddedObject(t *testing.T) {
	spec, e := loadSensor()
	if e != nil {
		t.Fatal(e)
	}
	if len(spec.Programs) != 7 || spec.Maps["events"].MaxEntries != 1<<20 {
		t.Fatal("object layout drift")
	}
}
