package network

import (
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestEndpoints(t *testing.T) {
	for _, x := range []struct {
		in, out string
		port    uint16
		v6      bool
	}{{"0100007F:0016", "127.0.0.1", 22, false}, {"00000000:1F90", "0.0.0.0", 8080, false}, {"00000000000000000000000001000000:0050", "::1", 80, true}, {"0000000000000000FFFF00000100007F:0050", "::ffff:127.0.0.1", 80, true}} {
		a, p, e := Endpoint(x.in, x.v6)
		if e != nil || a != x.out || p != x.port {
			t.Fatalf("%s => %s %d %v", x.in, a, p, e)
		}
	}
	if _, _, e := Endpoint("z:ffff", false); e == nil {
		t.Fatal("invalid endpoint")
	}
}
func TestTables(t *testing.T) {
	data := []byte("  sl local_address rem_address st tx_queue rx tr tm retr uid timeout inode\n0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 123\n")
	s, e := ParseTable(data, "tcp", false, "ns")
	if e != nil || len(s) != 1 || s[0].Inode != 123 || s[0].Exposure != domain.Potential {
		t.Fatalf("%+v %v", s, e)
	}
	if _, e := ParseTable([]byte("header\nbad"), "tcp", false, "ns"); e == nil {
		t.Fatal("bad table accepted")
	}
}
func FuzzSocket(f *testing.F) {
	f.Add("0100007F:0016", false)
	f.Fuzz(func(t *testing.T, s string, v bool) {
		if len(s) > 128 {
			return
		}
		_, _, _ = Endpoint(s, v)
	})
}
func FuzzSocketTable(f *testing.F) {
	f.Add("sl local_address rem_address st tx_queue rx tr tm retr uid timeout inode\n0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 123\n", false)
	f.Add("Num RefCount Protocol Flags Type St Inode Path\n1: 2 0 00010000 0001 01 123 /run/example.sock\n", true)
	f.Fuzz(func(t *testing.T, s string, isUnix bool) {
		if len(s) > 1<<20 {
			return
		}
		if isUnix {
			_, _ = ParseUnix([]byte(s), "n")
		} else {
			_, _ = ParseTable([]byte(s), "tcp", false, "n")
		}
	})
}
