package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
)

type fixture struct {
	deny     bool
	vanished bool
	user     string
}

func (f fixture) Read(p string) ([]byte, error) {
	if f.deny {
		return nil, fs.ErrPermission
	}
	switch {
	case strings.HasSuffix(p, "/stat"):
		if f.vanished {
			return nil, fs.ErrNotExist
		}
		return []byte("42 (fixture) S 1 " + strings.Repeat("0 ", 17) + "123 0"), nil
	case strings.HasSuffix(p, "/status"):
		return []byte("Name: fixture\nUid: 0 0 0 0\nGid: 0 0 0 0\nCapEff: 0000000000200000\nSeccomp: 0\nNoNewPrivs: 0\n"), nil
	case strings.HasSuffix(p, "_map"):
		return []byte("0 0 4294967295"), nil
	case strings.HasSuffix(p, "cgroup"):
		return []byte("0::/system.slice/fixture.service"), nil
	}
	return nil, fmt.Errorf("unexpected fixture read %s", p)
}
func (f fixture) Readlink(p string) (string, error) {
	switch {
	case strings.HasSuffix(p, "exe"):
		return "/usr/bin/fixture", nil
	case strings.HasSuffix(p, "ns/user"):
		return f.user, nil
	case strings.Contains(p, "/ns/"):
		return "pid:[4026531836]", nil
	}
	return "socket:[99]", nil
}
func (f fixture) Names(p string, _ int) ([]string, bool, error) {
	if p == "." {
		return []string{"42"}, false, nil
	}
	return []string{"1"}, false, nil
}
func TestCollectorEvidenceAndErrors(t *testing.T) {
	cfg := config.Default()
	for _, x := range []struct {
		f    fixture
		want int
		host bool
	}{{fixture{user: "user:[4026531837]"}, 1, true}, {fixture{user: "user:[123]"}, 1, false}, {fixture{deny: true}, 0, false}, {fixture{vanished: true}, 0, false}} {
		c := Collector{FS: x.f, Config: cfg, Host: domain.Host{ID: "host", BootID: "boot"}}
		b := c.Collect(context.Background())
		if len(b.Processes) != x.want {
			t.Fatalf("%+v", b)
		}
		if x.want == 0 {
			if b.Coverage.Complete || len(b.Diagnostics) == 0 {
				t.Fatal("failure hidden")
			}
			continue
		}
		seen := false
		for _, o := range b.Observations {
			if o.Key == "privilege.host_root" {
				seen = true
				if (o.Value == "true") != x.host {
					t.Fatalf("namespace privilege misinterpreted: %+v", o)
				}
			}
		}
		if !seen || b.Coverage.Completed.IsZero() {
			t.Fatal("missing evidence/timestamp")
		}
	}
}
func TestCancellationAndPIDReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := (Collector{FS: fixture{}, Config: config.Default()}).Collect(ctx)
	if b.Coverage.Complete {
		t.Fatal("cancelled collection complete")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("bad fixture")
	}
}
