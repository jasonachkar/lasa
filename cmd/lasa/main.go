package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/jasonachkar/lasa/internal/cli"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

// memoryHeadroom is the share of a cgroup memory limit used as the Go soft
// memory limit, leaving room for non-heap memory and the kernel's accounting.
const memoryHeadroom = 0.8

func main() {
	applyMemoryLimit()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	root := cli.New(os.Stdout, os.Stderr)
	err := root.ExecuteContext(ctx)
	if err != nil {
		mode, _ := root.PersistentFlags().GetString("diagnostics-format")
		cli.WriteError(os.Stderr, err, mode == "json")
	}
	os.Exit(cli.ExitCode(err))
}

// applyMemoryLimit makes the garbage collector honor a container or systemd
// memory limit (for example MemoryMax=) so large scans collect more often
// instead of being OOM-killed. An explicit GOMEMLIMIT always wins.
func applyMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	limit, ok := linux.CgroupMemoryLimit(linux.FS{Root: "/proc", Limit: 1 << 16}, linux.FS{Root: "/sys/fs/cgroup", Limit: 64}, os.Getpid())
	if ok {
		debug.SetMemoryLimit(int64(float64(limit) * memoryHeadroom))
	}
}
