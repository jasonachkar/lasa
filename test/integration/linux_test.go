//go:build linux

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/application"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
	"github.com/jasonachkar/lasa/internal/rules"
	"github.com/jasonachkar/lasa/rules/builtin"
)

func TestRealLinuxSocketOwnershipAndRoundTrip(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	pack, e := rules.Load(bytes.NewReader(builtin.YAML))
	if e != nil {
		t.Fatal(e)
	}
	c := config.Default()
	c.Roots = []string{t.TempDir()}
	c.Timeout = 10 * time.Second
	engine, e := application.Linux(c, pack)
	if e != nil {
		t.Fatal(e)
	}
	s, e := engine.Scan(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	self := ""
	for _, p := range s.Processes {
		if p.PID == os.Getpid() {
			self = p.ID
			if p.StartTime == 0 {
				t.Fatal("missing start identity")
			}
		}
	}
	if self == "" {
		t.Fatal("scanner process not observed")
	}
	for _, expected := range []struct {
		proto string
		port  int
	}{{"tcp", listener.Addr().(*net.TCPAddr).Port}, {"udp", udp.LocalAddr().(*net.UDPAddr).Port}} {
		found := false
		for _, sock := range s.Sockets {
			if sock.Protocol == expected.proto && int(sock.Port) == expected.port {
				for _, owner := range sock.Owners {
					if owner == self {
						found = true
						if sock.Exposure != domain.Local {
							t.Fatal("loopback misclassified")
						}
					}
				}
			}
		}
		if !found {
			t.Fatalf("live %s ownership not collected on port %d", expected.proto, expected.port)
		}
	}
	raw, e := report.Render(s, "json")
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := report.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	again, e := report.Render(decoded, "json")
	if e != nil || !bytes.Equal(raw, again) {
		t.Fatal("canonical report round-trip changed")
	}
	var v map[string]any
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
}
