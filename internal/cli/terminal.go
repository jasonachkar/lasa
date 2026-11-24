package cli

import (
	"io"
	"os"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
	"golang.org/x/sys/unix"
)

func renderReport(snapshot domain.Snapshot, format, output string, stdout io.Writer) ([]byte, error) {
	if format == "terminal" && output == "" {
		return report.RenderTerminal(snapshot, terminalOptions(stdout)), nil
	}
	return report.Render(snapshot, format)
}

func terminalOptions(stdout io.Writer) report.TerminalOptions {
	file, ok := stdout.(*os.File)
	if !ok {
		return report.TerminalOptions{}
	}
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return report.TerminalOptions{}
	}
	return report.TerminalOptions{
		Width: int(size.Col),
		Color: os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb",
	}
}
