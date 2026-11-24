package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// manCommand renders the lasa(1) manual page from the command tree, so the
// page always matches the binary's flags. It is hidden: packaging runs it to
// install /usr/share/man/man1/lasa.1.
func manCommand() *cobra.Command {
	return &cobra.Command{Use: "__man", Hidden: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		return writeMan(c.OutOrStdout(), c.Root())
	}}
}

func writeMan(w io.Writer, root *cobra.Command) error {
	var b strings.Builder
	b.WriteString(".TH LASA 1 \"\" \"lasa " + roff(root.Version) + "\" \"User Commands\"\n")
	b.WriteString(".SH NAME\nlasa \\- " + roff(root.Short) + "\n")
	b.WriteString(".SH SYNOPSIS\n.B lasa\n.I command\n[\\fIflags\\fR]\n")
	b.WriteString(".SH DESCRIPTION\nLASA collects bounded, read-only Linux metadata, evaluates local rules and reports conditional, evidence-backed findings with explicit coverage gaps. It never modifies the system, exploits services or uploads reports.\n")
	b.WriteString(".SH COMMANDS\n")
	var walk func(*cobra.Command, string)
	walk = func(c *cobra.Command, prefix string) {
		children := c.Commands()
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			if child.Hidden || child.Name() == "help" {
				continue
			}
			name := strings.TrimSpace(prefix + " " + child.Name())
			fmt.Fprintf(&b, ".SS \"lasa %s\"\n%s\n", roff(strings.TrimSpace(prefix+" "+child.Use)), roff(child.Short))
			if child.Example != "" {
				b.WriteString(".PP\nExamples:\n.nf\n" + roff(child.Example) + "\n.fi\n")
			}
			child.LocalFlags().VisitAll(func(f *pflag.Flag) {
				if f.Hidden || f.Name == "help" {
					return
				}
				fmt.Fprintf(&b, ".TP\n\\fB\\-\\-%s\\fR", roff(f.Name))
				if f.Value.Type() != "bool" {
					fmt.Fprintf(&b, " \\fI%s\\fR", roff(f.Value.Type()))
				}
				b.WriteString("\n" + roff(f.Usage))
				if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "[]" {
					b.WriteString(" (default: " + roff(f.DefValue) + ")")
				}
				b.WriteString("\n")
			})
			walk(child, name)
		}
	}
	walk(root, "")
	b.WriteString(".SH GLOBAL FLAGS\n")
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		fmt.Fprintf(&b, ".TP\n\\fB\\-\\-%s\\fR \\fI%s\\fR\n%s (default: %s)\n", roff(f.Name), roff(f.Value.Type()), roff(f.Usage), roff(f.DefValue))
	})
	b.WriteString(".SH EXIT STATUS\n.TP\n0\nCommand completed (a scan can be partial unless \\-\\-strict is used).\n.TP\n1\nA finding met \\-\\-fail\\-on, or diff found a new finding at \\-\\-fail\\-on\\-new.\n.TP\n2\nFatal command, configuration, platform, input or output error.\n.TP\n3\nStrict scan with incomplete collection; the report was still written.\n.TP\n130\nInterrupted.\n")
	b.WriteString(".SH ENVIRONMENT\n.TP\nNO_COLOR\nDisables color with \\-\\-color=auto.\n.TP\nSUDO_UID, SUDO_GID\nUnder sudo, allow writing a private report into the invoking user's directory and assign it to that user.\n")
	b.WriteString(".SH SEE ALSO\nhttps://lasa.secureobs.com/ and /usr/share/doc/lasa/\n")
	_, e := io.WriteString(w, b.String())
	return e
}

// roff escapes text for a roff body line.
func roff(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	s = strings.ReplaceAll(s, "-", `\-`)
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, ".") || strings.HasPrefix(line, "'") {
			line = `\&` + line
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
