package cli

import (
	"io"
	"os"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func renderReport(c *cobra.Command, snapshot domain.Snapshot, format, output string) ([]byte, error) {
	if format == "terminal" && output == "" {
		return report.RenderTerminal(snapshot, terminalOptions(c)), nil
	}
	return report.Render(snapshot, format)
}

// terminalOptions adapts layout to the destination. --color=auto colors only
// a terminal and honors NO_COLOR and TERM=dumb; always and never override.
func terminalOptions(c *cobra.Command) report.TerminalOptions {
	mode, _ := c.Flags().GetString("color")
	options := report.TerminalOptions{}
	width, tty := terminalWidth(c.OutOrStdout())
	if tty {
		options.Width = width
	}
	switch mode {
	case "always":
		options.Color = true
	case "never":
	default:
		options.Color = tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	}
	return options
}

func terminalWidth(stdout io.Writer) (int, bool) {
	file, ok := stdout.(*os.File)
	if !ok {
		return 0, false
	}
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, false
	}
	return int(size.Col), true
}
