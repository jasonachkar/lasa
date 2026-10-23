package inspection

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
)

type runtimeFunc func(context.Context, string) ([]byte, error)

func (f runtimeFunc) Get(c context.Context, p string) ([]byte, error) { return f(c, p) }
func TestRuntimeConfigurationAndSecretDiscard(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, priv := range []bool{false, true} {
		raw := []byte(`{"Id":"` + id + `","Name":"/fixture","State":{"Running":true,"Pid":42},"Config":{"User":"root","Env":["SECRET_KEY=NEVER_STORE_ME"]},"HostConfig":{"Privileged":` + map[bool]string{true: "true", false: "false"}[priv] + `,"PidMode":"private","IpcMode":"private","NetworkMode":"bridge","UsernsMode":"","ReadonlyRootfs":false,"CapAdd":[],"SecurityOpt":[]},"Mounts":[]}`)
		client := runtimeFunc(func(_ context.Context, p string) ([]byte, error) {
			switch {
			case p == "/version":
				return []byte(`{"ApiVersion":"1.47","MinAPIVersion":"1.24"}`), nil
			case strings.Contains(p, "/containers/json"):
				return []byte(`[{"Id":"` + id + `"}]`), nil
			default:
				return raw, nil
			}
		})
		b := (Collector{Module: "containers", Config: config.Default(), Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, Runtime: client}).Collect(context.Background())
		if !hasRisk(b, "containers.privileged", map[bool]string{true: "true", false: "false"}[priv]) {
			t.Fatal("privileged runtime setting missed", b)
		}
		saved, _ := json.Marshal(b)
		if strings.Contains(string(saved), "NEVER_STORE_ME") {
			t.Fatal("runtime environment retained")
		}
	}
}
func TestReadOnlyRuntimeSocketMountStillMatters(t *testing.T) {
	i := &inspection{c: Collector{Config: config.Default(), Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}}, seen: map[string]bool{}}
	var c ContainerInfo
	c.ID = strings.Repeat("b", 64)
	c.State.Running = true
	c.Mounts = append(c.Mounts, struct {
		Type, Source, Destination string
		RW                        bool
	}{Type: "bind", Source: "/run/docker.sock", Destination: "/run/docker.sock", RW: false})
	i.containerFacts(c)
	if !hasRisk(i.b, "containers.runtime_socket", "true") {
		t.Fatal("read-only bind mount was mistaken for socket API restriction")
	}
}
func TestUnixRuntimeNeverFollowsRedirectsOrUsesTCP(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "runtime.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(socket)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("mutating HTTP method")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://203.0.113.1/secret", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}), ReadHeaderTimeout: time.Second}
	go server.Serve(listener)
	defer server.Close()
	client, e := NewUnixRuntime(socket, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Transport.CloseIdleConnections()
	if _, e = client.Get(context.Background(), "/version"); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Get(context.Background(), "/redirect"); e == nil {
		t.Fatal("redirect accepted")
	}
}
