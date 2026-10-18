package identity

import "testing"

func TestInitialMapping(t *testing.T) {
	for _, v := range []struct {
		s    string
		want bool
	}{{"0 0 4294967295\n", true}, {"0 100000 65536", false}, {"garbage", false}, {"0 0 1", false}} {
		if InitialMapping(v.s) != v.want {
			t.Fatal(v)
		}
	}
}
func TestMountInfo(t *testing.T) {
	m, e := ParseMounts([]byte("23 1 8:1 / /mnt/a\\040b ro,nosuid shared:1 - ext4 /dev/vda ro\n"), "n")
	if e != nil || len(m) != 1 || m[0].Target != "/mnt/a b" {
		t.Fatalf("%+v %v", m, e)
	}
	if _, e := ParseMounts([]byte("bad"), "n"); e == nil {
		t.Fatal("invalid mount accepted")
	}
}
func FuzzMountInfo(f *testing.F) {
	f.Add("1 0 8:1 / / rw - ext4 /dev/sda rw\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		_, _ = ParseMounts([]byte(s), "n")
	})
}
