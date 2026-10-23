// Package inspection implements explicitly authorized configuration inspections.
package inspection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"golang.org/x/sys/unix"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// NativeRunner never invokes a shell or inherits caller-controlled executable,
// loader, locale, pager, or session-bus settings. It pins a trusted system tool.
type NativeRunner struct {
	Timeout time.Duration
	Limit   int
}
type cappedOutput struct {
	mu       sync.Mutex
	b        bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	overflow bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) > w.limit-w.b.Len() {
		w.overflow = true
		w.cancel()
		return 0, fmt.Errorf("native command output exceeds %d-byte budget", w.limit)
	}
	return w.b.Write(p)
}
func (n NativeRunner) Run(parent context.Context, tool string, args ...string) ([]byte, error) {
	if e := parent.Err(); e != nil {
		return nil, e
	}
	if strings.ContainsAny(tool, "/\\") {
		return nil, fmt.Errorf("tool must be an allowlisted basename")
	}
	allowed := map[string]bool{"systemctl": true, "sshd": true, "sudo": true, "nft": true, "dpkg-query": true, "rpm": true}
	if !allowed[tool] {
		return nil, fmt.Errorf("native tool %q is not authorized", tool)
	}
	timeout := n.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	limit := n.Limit
	if limit <= 0 {
		limit = 4 << 20
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var binary string
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		p, e := filepath.EvalSymlinks(filepath.Join(dir, tool))
		if e == nil {
			binary = p
			break
		}
	}
	if binary == "" {
		return nil, fmt.Errorf("required system tool %s is not installed", tool)
	}
	// Reject administrator mistakes as well as writable tool/ancestor substitution.
	for p := binary; p != "/"; p = filepath.Dir(p) {
		var us unix.Stat_t
		if e := unix.Stat(p, &us); e != nil {
			return nil, e
		}
		if us.Uid != 0 || us.Mode&0022 != 0 {
			return nil, fmt.Errorf("NATIVE_TOOL_UNTRUSTED: %s executable ancestry %s has uid=%d mode=%#o; require root ownership and no group/other writes: %w", tool, p, us.Uid, us.Mode, os.ErrPermission)
		}
	}
	h, e := linux.Open("/", strings.TrimPrefix(binary, "/"), unix.O_PATH)
	if e != nil {
		return nil, fmt.Errorf("pin %s: %w", tool, e)
	}
	defer h.Close()
	var st unix.Stat_t
	if e := unix.Fstat(int(h.Fd()), &st); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0111 == 0 || st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, fmt.Errorf("%s is not a trusted executable", tool)
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{h}
	cmd.Args[0] = binary
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0", "SYSTEMD_PAGERSECURE=1", "PAGER=cat"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		e := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(e, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return e
	}
	out := &cappedOutput{limit: limit, cancel: cancel}
	errOut := &cappedOutput{limit: 64 << 10, cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = errOut
	if e = cmd.Run(); e != nil {
		if out.overflow || errOut.overflow {
			return nil, fmt.Errorf("RESOURCE_LIMIT: %s command output exceeded its configured stdout/stderr budget", tool)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s command deadline or cancellation: %w", tool, ctx.Err())
		}
		return nil, fmt.Errorf("%s failed (%v): %s; raw command output withheld because configuration may contain secrets", tool, e, nativeFailure(errOut.b.String()))
	}
	return out.b.Bytes(), nil
}

var providerLocation = regexp.MustCompile(`(?m)(/[A-Za-z0-9_./@%+\-]+): (?:line )?([0-9]+):`)

func nativeFailure(stderr string) string {
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted"):
		return "native provider denied access in this namespace"
	case strings.Contains(lower, "not been booted with systemd") || strings.Contains(lower, "failed to connect to bus"):
		return "systemd system manager is unavailable in this namespace"
	case strings.Contains(lower, "unknown option -- g") || strings.Contains(lower, "illegal option -- g"):
		return "sshd does not support configuration-only -G mode; OpenSSH 9.3 or later is required"
	case strings.Contains(lower, "password is required") || strings.Contains(lower, "not allowed to") || strings.Contains(lower, "may not run sudo"):
		return "effective policy could not be queried noninteractively for the requested identity"
	}
	if match := providerLocation.FindStringSubmatch(stderr); len(match) > 0 {
		return "native provider rejected configuration at " + match[1] + ":" + match[2] + " (configuration values withheld)"
	}
	return "native provider rejected the query or its configuration; inspect its local diagnostic output"
}
