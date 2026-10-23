package inspection

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPrivilegedNativeSSHConfigurationOnly(t *testing.T) {
	if os.Getenv("LASA_PRIVILEGED_TESTS") != "1" {
		t.Skip("requires explicit disposable-VM authorization")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native SSH fixture requires root in the disposable VM")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "key-must-not-be-opened")
	if e := unix.Mkfifo(key, 0600); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "sshd_config")
	raw := fmt.Sprintf("HostKey %s\nPermitRootLogin yes\nPasswordAuthentication yes\nAuthenticationMethods any\nStrictModes yes\nMatch User fixture\n PasswordAuthentication no\n", key)
	if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	runner := NativeRunner{Timeout: 3 * time.Second}
	for user, want := range map[string]string{"root": "yes", "fixture": "no"} {
		output, e := runner.Run(context.Background(), "sshd", "-G", "-f", path, "-C", "user="+user+",host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22")
		if e != nil {
			t.Fatal("configuration-only SSH query failed or attempted to open the host-key FIFO", e)
		}
		settings, e := sshSettings(output)
		if e != nil || settings["passwordauthentication"] != want {
			t.Fatal("native Match condition not respected", settings, e)
		}
	}
}
