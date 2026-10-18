//go:build linux

package integration

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	sensor "github.com/jasonachkar/lasa/internal/collector/ebpf"
)

func TestPrivilegedSensorEventDelivery(t *testing.T) {
	if os.Getenv("LASA_PRIVILEGED_TESTS") != "1" {
		t.Skip("requires an explicitly authorized disposable Linux VM with BTF/tracefs and BPF/perf permissions")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			cmd := exec.CommandContext(ctx, "/bin/true")
			_ = cmd.Run()
			l, e := net.Listen("tcp4", "127.0.0.1:0")
			if e == nil {
				done := make(chan struct{})
				go func() {
					defer close(done)
					c, e := l.Accept()
					if e == nil {
						_ = c.Close()
					}
				}()
				c, e := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
				if e == nil {
					_ = c.Close()
				}
				_ = l.Close()
				<-done
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	b := (sensor.Collector{Duration: 3 * time.Second, MaxEvents: 4096, BootID: "test"}).Collect(ctx)
	if len(b.Diagnostics) > 0 {
		for _, d := range b.Diagnostics {
			t.Log(d.Error())
		}
	}
	if !b.Coverage.Complete {
		t.Fatal("sensor could not attach every configured source")
	}
	kinds := map[string]bool{}
	for _, e := range b.RuntimeEvents {
		kinds[e.Kind] = true
	}
	for _, kind := range []string{"process_exec", "connect_attempt", "bind_attempt", "accepted_connection"} {
		if !kinds[kind] {
			t.Errorf("no real %s event delivered", kind)
		}
	}
}
