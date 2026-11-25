package identity

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

func TestCollectUsesLowestPIDAndTracksUnknownMounts(t *testing.T) {
	root := t.TempDir()
	for path, content := range map[string]string{
		"20/mountinfo": "23 1 8:1 / /mnt/a\\040b ro,nosuid - ext4 /dev/vda ro\n",
		"22/mountinfo": "malformed mount information\n",
	} {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := Collector{FS: linux.FS{Root: root}, Processes: []domain.Process{
		{PID: 21, Namespaces: map[string]string{"mnt": "mount-a"}},
		{PID: 20, Namespaces: map[string]string{"mnt": "mount-a"}},
		{PID: 22, Namespaces: map[string]string{"mnt": "mount-b"}},
		{PID: 23, Namespaces: map[string]string{"mnt": "mount-c"}},
	}}
	b := c.Collect(context.Background())
	if len(b.Mounts) != 1 || b.Mounts[0].Target != "/mnt/a b" || len(b.Observations) != 1 {
		t.Fatalf("mount evidence: %+v, %+v", b.Mounts, b.Observations)
	}
	if b.Coverage.Attempted != 3 || b.Coverage.Successful != 1 || b.Coverage.Inconclusive != 2 || b.Coverage.Complete {
		t.Fatalf("incorrect mount coverage: %+v", b.Coverage)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b := c.Collect(ctx); len(b.Mounts) != 0 || b.Coverage.Inconclusive != 1 {
		t.Fatalf("canceled collection proceeded: %+v", b)
	}
}
