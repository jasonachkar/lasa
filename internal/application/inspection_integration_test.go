package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/access"
	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/inspection"
	"github.com/jasonachkar/lasa/internal/report"
	"github.com/jasonachkar/lasa/internal/rules"
	"github.com/jasonachkar/lasa/rules/builtin"
)

type policyFixtureFS struct{}

func (policyFixtureFS) Read(path string) ([]byte, error) {
	switch path {
	case "etc/passwd":
		return []byte("root:x:0:0:private:/root:/bin/sh\ndeploy:x:1001:1001:private:/home/deploy:/bin/sh\n"), nil
	case "etc/group":
		return []byte("root:x:0:\ndeploy:x:1001:deploy\n"), nil
	}
	return nil, os.ErrNotExist
}
func (policyFixtureFS) Readlink(string) (string, error)           { return "", os.ErrNotExist }
func (policyFixtureFS) Names(string, int) ([]string, bool, error) { return nil, false, nil }

type nativePolicyFixture struct{}

func (f nativePolicyFixture) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "sshd" {
		return []byte("permitrootlogin yes\npasswordauthentication yes\nauthenticationmethods any\nstrictmodes yes\n"), nil
	}
	if args[0] == "list-units" {
		return []byte(`[{"unit":"example.service"}]`), nil
	}
	if args[0] == "list-unit-files" {
		return []byte(`[]`), nil
	}
	return []byte("Id=example.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nUser=root\nGroup=root\nDynamicUser=no\nRootDirectory=\nRootImage=\nWorkingDirectory=/\nEnvironmentFiles=\nMainPID=0\nExecStart={ path=/opt/example/service ; argv[]=/opt/example/service SUPER_PRIVATE_ARGUMENT ; ignore_errors=no ; pid=0 }\nExecStartPre=\nExecStartPost=\nExecReload=\nExecStop=\nFragmentPath=/etc/systemd/system/example.service\nDropInPaths=\nNoNewPrivileges=yes\nProtectSystem=strict\nPrivateUsers=no\n"), nil
}
func TestInspectionPipelineFindingsGraphAndAllReportFormats(t *testing.T) {
	pack, e := rules.Load(bytes.NewReader(builtin.YAML))
	if e != nil {
		t.Fatal(e)
	}
	cfg := config.Default()
	cfg.Inspect = []string{"systemd", "ssh"}
	for _, writable := range []bool{true, false} {
		engine := Engine{Host: domain.Host{ID: "fixture-host", BootID: "fixture-boot"}, Rules: pack, Stages: []Stage{func(s *domain.Snapshot) []collector.Collector {
			return []collector.Collector{inspection.Collector{Module: "systemd", Config: cfg, Snapshot: s, Runner: nativePolicyFixture{}, FS: policyFixtureFS{}, CheckAccess: func(_ context.Context, path string, _ []access.Account) (access.Result, error) {
				r := access.Result{Target: path}
				if writable {
					r.Writers = []access.Account{{Name: "deploy", UID: 1001}}
					r.Paths = []string{path}
				}
				return r, nil
			}}, inspection.Collector{Module: "ssh", Config: cfg, Snapshot: s, Runner: nativePolicyFixture{}}}
		}}}
		s, e := engine.Scan(context.Background(), cfg)
		if e != nil {
			t.Fatal(e)
		}
		found := map[string]bool{}
		for _, f := range s.Findings {
			found[f.RuleID] = true
			if len(f.Evidence) == 0 || len(f.Path.Entities) == 0 {
				t.Fatal("finding missing evidence graph")
			}
		}
		if found["LASA-101"] != writable || !found["LASA-110"] {
			t.Fatalf("fixture detection incorrect %t %+v", writable, found)
		}
		for _, format := range []string{"json", "terminal", "html", "sarif"} {
			raw, e := report.Render(s, format)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(raw), "SUPER_PRIVATE_ARGUMENT") {
				t.Fatal("secret argument leaked into", format)
			}
			if format == "json" {
				decoded, e := report.Decode(raw)
				if e != nil {
					t.Fatalf("inspection report contract invalid: %v", e)
				}
				again, _ := report.Render(decoded, "json")
				if !bytes.Equal(raw, again) {
					t.Fatal("inspection round trip changed data")
				}
			}
			if format == "sarif" {
				var v map[string]any
				if json.Unmarshal(raw, &v) != nil || v["version"] != "2.1.0" {
					t.Fatal("invalid SARIF")
				}
			}
		}
		if len(s.Assets) != 2 || s.ScopeFingerprint == "" || len(s.Graph.Edges) != 2 {
			t.Fatal(fmt.Sprint("inspection provenance missing: ", s.Graph))
		}
	}
}
