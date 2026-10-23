package advisory

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNativeVersionSemantics(t *testing.T) {
	cases := []struct {
		d, a, b string
		want    int
	}{{"debian:bookworm", "1.0~rc1", "1.0", -1}, {"debian:12", "1:1.0-1", "2.0-1", 1}, {"ubuntu:24.04", "1.0-1ubuntu2.10", "1.0-1ubuntu2.9", 1}, {"debian:13", "1.0", "1.0-0", 0}, {"debian:13", "1.0+deb12u1", "1.0", 1}, {"rhel:9", "0:1.0-9.el9", "0:1.0-10.el9", -1}, {"rocky:9", "1:1.0-1", "0:99.0-1", 1}, {"almalinux:9", "1.0~rc1-1", "1.0-1", -1}, {"rhel:9", "1.0^git1", "1.0", 1}, {"rhel:9", "1.0^git1", "1.0.1", -1}, {"fedora:43", "1.001-1", "1.1-1", 0}, {"fedora:43", "1.0a", "1.0.1", -1}}
	for _, tt := range cases {
		got, e := Compare(tt.d, tt.a, tt.b)
		if e != nil || got != tt.want {
			t.Fatalf("%s %s / %s got=%d err=%v want=%d", tt.d, tt.a, tt.b, got, e, tt.want)
		}
		inverse, e := Compare(tt.d, tt.b, tt.a)
		if e != nil || inverse != -got {
			t.Fatal("non-symmetric comparison")
		}
	}
	if _, e := Compare("unknown:1", "1", "2"); e == nil {
		t.Fatal("unsupported version scheme accepted")
	}
	if _, e := Compare("debian:13", "x:1", "1"); e == nil {
		t.Fatal("invalid epoch accepted")
	}
}
func TestDebianComparatorAgainstNativeDpkg(t *testing.T) {
	if _, e := exec.LookPath("dpkg"); e != nil {
		t.Skip("native dpkg unavailable")
	}
	versions := []string{"1.0", "1.0-0", "1.0~beta2", "1.0~beta10", "1:0.1-1", "2.0+really1.0-3", "2.0-1+deb12u1", "2.0-1~bpo12+1", "1.0~~", "1.0a", "1.0.a"}
	for _, a := range versions {
		for _, b := range versions {
			c, e := Compare("debian:12", a, b)
			if e != nil {
				t.Fatal(e)
			}
			op := "eq"
			if c < 0 {
				op = "lt"
			}
			if c > 0 {
				op = "gt"
			}
			if e := exec.Command("dpkg", "--compare-versions", a, op, b).Run(); e != nil {
				t.Fatalf("dpkg disagrees: %s %s %s (%v)", a, op, b, e)
			}
		}
	}
}
func TestFeedFreshnessAndBackports(t *testing.T) {
	now := time.Now().UTC()
	db := Database{Schema: Schema, Source: "vendor fixture", FetchedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Records: []Record{{ID: "CVE-fixture", Distribution: "debian:bookworm", Package: "openssl", SourcePackage: true, Fixed: "3.0.11-1~deb12u2", Severity: "high"}}}
	raw, _ := json.Marshal(db)
	decoded, e := Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = decoded.Fresh(now, 2*time.Hour); e != nil {
		t.Fatal(e)
	}
	if e = decoded.Fresh(now, 30*time.Minute); e == nil {
		t.Fatal("stale feed accepted")
	}
	r := db.Records[0]
	for version, want := range map[string]bool{"3.0.11-1~deb12u1": true, "3.0.11-1~deb12u2": false, "3.0.11-1~deb12u3": false} {
		got, e := Affected("debian:bookworm", version, r)
		if e != nil || got != want {
			t.Fatalf("%s got %t %v", version, got, e)
		}
	}
	if yes, _ := Affected("debian:trixie", "3.0.0", r); yes {
		t.Fatal("release mismatch was ignored")
	}
	db.Records = append(db.Records, db.Records[0])
	raw, _ = json.Marshal(db)
	if _, e := Decode(raw); e == nil {
		t.Fatal("duplicate advisory accepted")
	}
	if _, e := Decode(append(raw, []byte(" {}")...)); e == nil {
		t.Fatal("trailing feed accepted")
	}
}
func TestDebianTrackerConversion(t *testing.T) {
	now := time.Now().UTC()
	base := Database{Schema: Schema, Source: "official fixture", FetchedAt: now, ExpiresAt: now.Add(time.Hour)}
	raw := []byte(`{"openssl":{"CVE-1":{"releases":{"bookworm":{"status":"resolved","fixed_version":"3.0.1-1+deb12u2","urgency":"high"}}},"CVE-2":{"releases":{"bookworm":{"status":"resolved","fixed_version":"0","urgency":"low"}}},"CVE-3":{"releases":{"bookworm":{"status":"open","fixed_version":"","urgency":"medium"}}}}}`)
	db, e := DebianData(context.Background(), raw, "bookworm", base)
	if e != nil || len(db.Records) != 2 {
		t.Fatalf("%+v %v", db, e)
	}
	if _, e := DebianData(context.Background(), raw, "missing", base); e == nil {
		t.Fatal("unknown release accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := DebianData(ctx, raw, "bookworm", base); e == nil {
		t.Fatal("cancel ignored")
	}
}
func FuzzVersionComparators(f *testing.F) {
	for _, s := range []string{"1.0", "1:2.0~rc1-1", "1.0^git1", ""} {
		f.Add(s, "1.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 512 || len(b) > 512 {
			return
		}
		for _, dist := range []string{"debian:13", "rhel:9"} {
			ab, e := Compare(dist, a, b)
			if e != nil {
				continue
			}
			ba, e := Compare(dist, b, a)
			if e != nil || ab != -ba {
				t.Fatalf("asymmetric %q / %q", a, b)
			}
			if strings.ContainsAny(a+b, "\x00\r\n\t ") {
				t.Fatal("invalid version accepted")
			}
		}
	})
}

func TestUndeterminedVendorAssessmentRemainsUnknown(t *testing.T) {
	now := time.Now().UTC()
	base := Database{Schema: Schema, Source: "official fixture", FetchedAt: now, ExpiresAt: now.Add(time.Hour)}
	raw := []byte(`{"example":{"VENDOR-EXAMPLE":{"releases":{"trixie":{"status":"undetermined","fixed_version":"","urgency":"high"}}}}}`)
	db, err := DebianData(context.Background(), raw, "trixie", base)
	if err != nil || len(db.Records) != 1 || !db.Records[0].Uncertain {
		t.Fatalf("uncertainty discarded: %+v %v", db, err)
	}
	if affected, err := Affected("debian:trixie", "1.0", db.Records[0]); err == nil || affected {
		t.Fatal("undetermined assessment became a conclusion")
	}
	if err := db.Fresh(now.Add(2*time.Hour), 0); err == nil {
		t.Fatal("own expiry bypassed with age check disabled")
	}
	db.FetchedAt = now.Add(10 * time.Minute)
	if err := db.Fresh(now, 0); err == nil {
		t.Fatal("future provenance accepted")
	}
}
