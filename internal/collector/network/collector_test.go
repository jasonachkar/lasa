package network

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

func TestCollectUsesVisibleNamespaceRepresentative(t *testing.T) {
	root := t.TempDir()
	put := func(path, content string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	const header = "sl local_address rem_address st tx_queue rx tr tm retr uid timeout inode\n"
	put("21/net/tcp", header+"0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 123\n")
	put("21/net/udp", "header\ninvalid\n")
	put("21/net/unix", "Num RefCount Protocol Flags Type St Inode Path\n1: 2 0 00010000 0001 01 456 /run/example.sock\n")
	put(strconv.Itoa(os.Getpid())+"/net/route", "synthetic route\n")
	c := Collector{FS: linux.FS{Root: root}, Processes: []domain.Process{
		{ID: "owner", PID: 20, Namespaces: map[string]string{"net": "ns"}, SocketInodes: []uint64{123}},
		{ID: "peer", PID: 21, Namespaces: map[string]string{"net": "ns"}},
	}}
	b := c.Collect(context.Background())
	if len(b.Sockets) != 2 || b.Sockets[0].Inode != 123 || len(b.Sockets[0].Owners) != 1 || b.Sockets[0].Owners[0] != "owner" || b.Sockets[1].Inode != 456 {
		t.Fatalf("unexpected socket inventory: %+v", b.Sockets)
	}
	if b.Coverage.Complete || b.Coverage.Inconclusive < 3 {
		t.Fatalf("missing or malformed tables must be inconclusive: %+v", b.Coverage)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b := c.Collect(ctx); len(b.Sockets) != 0 || b.Coverage.Inconclusive != 1 {
		t.Fatalf("canceled collection proceeded: %+v", b)
	}
}
