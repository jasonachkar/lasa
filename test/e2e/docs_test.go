package e2e

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// externalFlags are documented options of other programs (curl, apt,
// useradd, systemctl, docker) shown in installation and deployment steps.
var externalFlags = map[string]bool{
	"--proto": true, "--tlsv1": true, "--only-upgrade": true, "--system": true, "--user-group": true,
	"--no-create-home": true, "--shell": true, "--now": true, "--rm": true, "--read-only": true,
	"--cap-drop": true, "--security-opt": true, "--privileged": true, "--help": true,
	"--repo": true, "--network": true, "--batch": true, "--verify": true,
}

// TestDocumentedCommandsAndFlagsExist keeps customer documentation from
// describing options the shipped binary does not have.
func TestDocumentedCommandsAndFlagsExist(t *testing.T) {
	root := cli.New(io.Discard, io.Discard)
	flags := map[string]bool{}
	commands := map[string]bool{}
	var walk func(*cobra.Command, string)
	walk = func(c *cobra.Command, path string) {
		commands[path] = true
		c.Flags().VisitAll(func(f *pflag.Flag) { flags["--"+f.Name] = true })
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) { flags["--"+f.Name] = true })
		for _, child := range c.Commands() {
			walk(child, strings.TrimSpace(path+" "+child.Name()))
		}
	}
	walk(root, "")
	pages, _ := filepath.Glob("../../docs/customer/*.md")
	pages = append(pages, "../../docs/website/index.md")
	if len(pages) < 2 {
		t.Fatal("customer documentation not found")
	}
	flagPattern := regexp.MustCompile("(?:^|[\\s`(\\[])(--[a-z][a-z0-9-]+)")
	commandPattern := regexp.MustCompile("`lasa ([a-z]+)(?: ([a-z]+))?")
	for _, page := range pages {
		raw, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, m := range flagPattern.FindAllStringSubmatch(text, -1) {
			if !flags[m[1]] && !externalFlags[m[1]] {
				t.Errorf("%s documents %s, which no lasa command provides", filepath.Base(page), m[1])
			}
		}
		for _, m := range commandPattern.FindAllStringSubmatch(text, -1) {
			if !commands[m[1]] {
				t.Errorf("%s documents `lasa %s`, which is not a command", filepath.Base(page), m[1])
			} else if m[2] != "" && len(commands) > 0 {
				if _, nested := hasChildren(root, m[1]); nested && !commands[m[1]+" "+m[2]] {
					t.Errorf("%s documents `lasa %s %s`, which is not a command", filepath.Base(page), m[1], m[2])
				}
			}
		}
	}
}

func hasChildren(root *cobra.Command, name string) (*cobra.Command, bool) {
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c, len(c.Commands()) > 0
		}
	}
	return nil, false
}
