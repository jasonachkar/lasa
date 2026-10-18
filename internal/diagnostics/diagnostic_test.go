package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestActionableErrno(t *testing.T) {
	d := New("process", "read", "42/status", fmt.Errorf("wrapped: %w", syscall.EACCES))
	if d.Code != "PERMISSION_DENIED" || d.Errno != int(syscall.EACCES) || d.Target != "42/status" || d.Remediation == "" || d.Impact == "" || strings.Contains(d.Remediation, "CAP_SYS_ADMIN") {
		t.Fatalf("%+v", d)
	}
	if d := New("scan", "collect", "host", context.DeadlineExceeded); d.Code != "SCAN_CANCELLED" {
		t.Fatal(d)
	}
}
