package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jasonachkar/lasa/internal/cli"
)

func main() {
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
