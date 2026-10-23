package inspection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/access"
	"github.com/jasonachkar/lasa/internal/advisory"
	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/storage"
	"golang.org/x/sys/unix"
)

type fakeFS map[string]string

func (f fakeFS) Read(path string) ([]byte, error) {
	s, ok := f[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(s), nil
}
func (f fakeFS) Readlink(string) (string, error) { return "", os.ErrNotExist }
func (f fakeFS) Names(path string, limit int) ([]string, bool, error) {
	var names []string
	for p := range f {
		if filepath.Dir(p) == path {
			names = append(names, filepath.Base(p))
		}
	}
	slices.Sort(names)
	cut := len(names) > limit
	if cut {
		names = names[:limit]
	}
	return names, cut, nil
}

type runnerFunc func(context.Context, string, ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	return f(ctx, tool, args...)
}
func identities() fakeFS {
	return fakeFS{"etc/passwd": "root:x:0:0:private:/root:/bin/sh\ndeploy:x:1001:1001:secret:/home/deploy:/bin/sh\n", "etc/group": "root:x:0:\ndeploy:x:1001:deploy\n"}
}
func fixtureAccess(writable string) func(context.Context, string, []access.Account) (access.Result, error) {
	return func(ctx context.Context, path string, accounts []access.Account) (access.Result, error) {
		if e := ctx.Err(); e != nil {
			return access.Result{}, e
		}
		r := access.Result{Target: path, Metadata: []access.Metadata{{Path: path, Mode: 0100644, UID: 0, GID: 0, MountID: 1}}}
		if path == writable && len(accounts) > 0 {
			r.Writers = []access.Account{{Name: "deploy", UID: 1001, GID: 1001}}
			r.Paths = []string{path}
		}
		return r, nil
	}
}
func hasRisk(b domain.Batch, key string, value string) bool {
	for _, o := range b.Observations {
		if o.Key == key && o.State == domain.Observed && o.Value == value {
			return true
		}
	}
	return false
}
func effectiveService() string {
	return "Id=example.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nUser=root\nGroup=root\nDynamicUser=no\nRootDirectory=\nRootImage=\nWorkingDirectory=/\nEnvironmentFiles=\nMainPID=42\nExecStart={ path=/usr/bin/bash ; argv[]=/usr/bin/bash /opt/service/job.sh SECRET_TOKEN_VALUE ; ignore_errors=no ; start_time=n/a ; stop_time=n/a ; pid=0 ; code=(null) ; status=0/0 }\nExecStartPre=\nExecStartPost=\nExecReload=\nExecStop=\nFragmentPath=/etc/systemd/system/example.service\nDropInPaths=\nNoNewPrivileges=no\nProtectSystem=no\nPrivateUsers=no\n"
}
func TestSystemdEffectiveExecutionAndSecretOmission(t *testing.T) {
	for _, writable := range []bool{true, false} {
		snapshot := domain.Snapshot{Host: domain.Host{ID: "host"}}
		runner := runnerFunc(func(_ context.Context, tool string, args ...string) ([]byte, error) {
			cmd := strings.Join(args, " ")
			if tool != "systemctl" {
				t.Fatal(tool)
			}
			if strings.HasPrefix(cmd, "list-units") {
				return []byte(`[{"unit":"example.service"}]`), nil
			}
			if strings.HasPrefix(cmd, "list-unit-files") {
				return []byte(`[]`), nil
			}
			return []byte(effectiveService()), nil
		})
		target := ""
		if writable {
			target = "/opt/service/job.sh"
		}
		b := (Collector{Module: "systemd", Config: config.Default(), Snapshot: &snapshot, Runner: runner, FS: identities(), CheckAccess: fixtureAccess(target)}).Collect(context.Background())
		if !hasRisk(b, "systemd.writable_execution", fmt.Sprint(writable)) {
			t.Fatalf("expected writable=%t: %+v", writable, b)
		}
		raw, _ := json.Marshal(b)
		if strings.Contains(string(raw), "SECRET_TOKEN_VALUE") {
			t.Fatal("argv secret retained")
		}
		if !b.Coverage.Complete {
			t.Fatalf("complete effective fixture unexpectedly partial: %+v", b.Diagnostics)
		}
	}
}
func TestSystemdMissingPropertyAndInlineCommandAreUnknown(t *testing.T) {
	for _, response := range []string{strings.Replace(effectiveService(), "User=root\n", "", 1), strings.Replace(effectiveService(), "/usr/bin/bash /opt/service/job.sh SECRET_TOKEN_VALUE", "/usr/bin/bash -c echo_SECRET", 1)} {
		runner := runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[0] == "list-units" {
				return []byte(`[{"unit":"example.service"}]`), nil
			}
			if args[0] == "list-unit-files" {
				return []byte(`[]`), nil
			}
			return []byte(response), nil
		})
		b := (Collector{Module: "systemd", Config: config.Default(), Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, FS: identities(), Runner: runner, CheckAccess: fixtureAccess("")}).Collect(context.Background())
		if b.Coverage.Complete || hasRisk(b, "systemd.writable_execution", "true") {
			t.Fatalf("unsupported policy became a valid conclusion: %+v", b)
		}
	}
}
func TestSSHContextsAndMultifactor(t *testing.T) {
	base := "permitrootlogin yes\npasswordauthentication yes\nauthenticationmethods any\nstrictmodes yes\nauthorizedkeysfile .ssh/authorized_keys\n"
	for _, tt := range []struct {
		methods string
		want    bool
	}{{"any", true}, {"password", true}, {"publickey,password", false}, {"publickey,password publickey,keyboard-interactive", false}} {
		runner := runnerFunc(func(_ context.Context, tool string, args ...string) ([]byte, error) {
			if tool != "sshd" || args[0] != "-G" {
				t.Fatal("unsafe ssh invocation", tool, args)
			}
			return []byte(strings.Replace(base, "authenticationmethods any", "authenticationmethods "+tt.methods, 1)), nil
		})
		b := (Collector{Module: "ssh", Config: config.Default(), Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, Runner: runner}).Collect(context.Background())
		if !hasRisk(b, "ssh.root_password", fmt.Sprint(tt.want)) {
			t.Fatalf("methods %s: %+v", tt.methods, b)
		}
	}
	for _, s := range []string{"user=root", "user=root,host=x,addr=x,laddr=x,lport=22,user=evil", "user=root,host=x,addr=x,laddr=x,lport=22\n"} {
		if sshContext(s) == nil {
			t.Fatalf("invalid context accepted: %q", s)
		}
	}
}
func TestSudoEffectiveGrants(t *testing.T) {
	raw := "Matching Defaults entries for deploy on host:\n    env_reset\n\nSudoers entry:\n    RunAsUsers: ALL\n    Options: !authenticate\n    Commands:\n        ALL\n"
	grants, e := sudoGrants([]byte(raw))
	if e != nil || len(grants) != 1 || !grants[0].Root || !grants[0].All || !grants[0].NoPassword {
		t.Fatalf("%+v %v", grants, e)
	}
	if _, e := sudoGrants([]byte("malformed native output")); e == nil {
		t.Fatal("unknown sudo format accepted")
	}
	runner := runnerFunc(func(_ context.Context, _ string, _ ...string) ([]byte, error) { return []byte(raw), nil })
	b := (Collector{Module: "sudo", Config: config.Default(), Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, Runner: runner, FS: identities(), CheckAccess: fixtureAccess("")}).Collect(context.Background())
	if !hasRisk(b, "sudo.passwordless_root", "true") {
		t.Fatalf("grant missed %+v", b)
	}
}
func TestPermissionInspectionKnownWriter(t *testing.T) {
	s := domain.Snapshot{Host: domain.Host{ID: "h"}, Files: []domain.File{{Path: "/usr/bin/privileged", Mode: 0104755, UID: 0}}}
	b := (Collector{Module: "permissions", Config: config.Default(), Snapshot: &s, FS: identities(), CheckAccess: fixtureAccess("/usr/bin/privileged")}).Collect(context.Background())
	if !hasRisk(b, "permissions.privileged_write", "true") {
		t.Fatalf("write path missed: %+v", b)
	}
}
func TestFailuresBudgetsAndCancellation(t *testing.T) {
	for _, module := range config.InspectionModules {
		t.Run(module, func(t *testing.T) {
			runner := runnerFunc(func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
				return nil, errors.New("required provider unavailable")
			})
			cfg := config.Default()
			cfg.ContainerSocket = "/nonexistent/lasa-runtime"
			b := (Collector{Module: module, Config: cfg, Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, Runner: runner, FS: fakeFS{}}).Collect(context.Background())
			if module == "permissions" && !b.Coverage.Complete {
				return
			}
			if b.Coverage.Complete {
				t.Fatal("missing prerequisites silently complete", b)
			}
			for _, d := range b.Diagnostics {
				if d.Component == "" || d.Operation == "" || d.Target == "" || d.Cause == "" || d.Impact == "" || d.Remediation == "" {
					t.Fatal("incomplete diagnostic", d)
				}
			}
		})
	}
	if b := (Collector{Module: "ssh"}).Collect(context.Background()); b.Coverage.Complete {
		t.Fatal("nil snapshot accepted")
	}
	cfg := config.Default()
	cfg.MaxInspectionItems = 1
	cfg.SSHContexts = []string{"user=root,host=x,addr=127.0.0.1,laddr=127.0.0.1,lport=22", "user=deploy,host=x,addr=127.0.0.1,laddr=127.0.0.1,lport=22"}
	b := (Collector{Module: "ssh", Config: cfg, Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, Runner: runnerFunc(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("permitrootlogin no\npasswordauthentication no\nauthenticationmethods any\nstrictmodes yes\n"), nil
	})}).Collect(context.Background())
	if b.Coverage.Complete || b.Coverage.Skipped == 0 {
		t.Fatal("item truncation hidden")
	}
}
func TestPackageNativeInventoryAndFreshAdvisories(t *testing.T) {
	fs := identities()
	fs["usr/lib/os-release"] = "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"
	db := advisory.Database{Schema: advisory.Schema, Source: "vendor fixture", FetchedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour), Records: []advisory.Record{{ID: "CVE-test", Distribution: "debian:bookworm", Package: "openssl", SourcePackage: true, Fixed: "3.0.1-1+deb12u2", Severity: "high"}}}
	raw, _ := json.Marshal(db)
	dir := t.TempDir()
	path := filepath.Join(dir, "advisories.json")
	if e := storage.Atomic(path, raw); e != nil {
		t.Fatal(e)
	}
	cfg := config.Default()
	cfg.AdvisoryFile = path
	for version, want := range map[string]bool{"3.0.1-1+deb12u1": true, "3.0.1-1+deb12u2": false} {
		runner := runnerFunc(func(_ context.Context, tool string, _ ...string) ([]byte, error) {
			if tool != "dpkg-query" {
				t.Fatal(tool)
			}
			return []byte("libssl3\t" + version + "\topenssl\t" + version + "\tamd64\tii \n"), nil
		})
		b := (Collector{Module: "packages", Config: cfg, Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, FS: fs, Runner: runner}).Collect(context.Background())
		if !hasRisk(b, "packages.vulnerable", fmt.Sprint(want)) {
			t.Fatalf("native version %s: %+v", version, b)
		}
	}
}
func TestNativeRunnerPinsTrustedToolAndBoundsOutput(t *testing.T) {
	runner := NativeRunner{Timeout: time.Second}
	if _, e := runner.Run(context.Background(), "sh", "-c", "echo unsafe"); e == nil {
		t.Fatal("shell execution allowed")
	}
	raw, e := runner.Run(context.Background(), "dpkg-query", "--version")
	if e != nil {
		t.Skipf("trusted native dpkg-query unavailable: %v", e)
	}
	if !strings.Contains(string(raw), "Debian") {
		t.Fatal("native query did not run")
	}
	runner.Limit = 1
	if _, e := runner.Run(context.Background(), "dpkg-query", "--version"); e == nil {
		t.Fatal("output limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := runner.Run(ctx, "dpkg-query", "--version"); e == nil {
		t.Fatal("cancellation ignored")
	}
}

func FuzzConfigurationParsers(f *testing.F) {
	f.Add("User=root\nExecStart=\n")
	f.Add("Sudoers entry:\n    RunAsUsers: root\n    Commands:\n        /usr/bin/id\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		_, _ = properties([]byte(s))
		_, _ = executionPaths(s)
		_, _ = nativeWords(s)
		_, _ = sshSettings([]byte(s))
		_, _ = sudoGrants([]byte(s))
		_, _ = PackageInventory([]byte(s), true)
		_, _ = ParseCron([]byte(s), "")
	})
}

func TestEnvironmentFilesAndRelativeServiceScripts(t *testing.T) {
	paths, e := environmentPaths("/etc/default/example (ignore_errors=yes) /etc/service.env (ignore_errors=no)")
	if e != nil || len(paths) != 2 {
		t.Fatalf("%v %v", paths, e)
	}
	if _, e := environmentPaths("/etc/file with spaces (ignore_errors=no)"); e == nil {
		t.Fatal("ambiguous environment file accepted")
	}
	paths, e = executionPathsAt("{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 service.py ; ignore_errors=no ; pid=0 }", "/opt/app")
	if e != nil || !slices.Contains(paths, "/opt/app/service.py") {
		t.Fatalf("effective working directory not applied: %v %v", paths, e)
	}
}
func TestSudoNegatedRootAndCommandRestrictions(t *testing.T) {
	grants, e := sudoGrants([]byte("Sudoers entry:\n RunAsUsers: ALL, !root\n Commands:\n ALL\n"))
	if e != nil || grants[0].Root {
		t.Fatal("negated root ignored", grants, e)
	}
	grants, e = sudoGrants([]byte("Sudoers entry:\n RunAsUsers: root\n Commands:\n ALL\n !/usr/bin/id\n"))
	if e != nil || grants[0].All {
		t.Fatal("restricted ALL labeled unrestricted", grants, e)
	}
}

func TestProviderFailuresDoNotEchoSecrets(t *testing.T) {
	cases := map[string]string{"/etc/ssh/sshd_config: line 12: Bad configuration option: SECRET": "/etc/ssh/sshd_config:12", "System has not been booted with systemd as init system": "systemd system manager is unavailable", "failed: Permission denied SECRET": "native provider denied access"}
	for raw, want := range cases {
		got := nativeFailure(raw)
		if !strings.Contains(got, want) || strings.Contains(got, "SECRET") {
			t.Fatalf("unsafe/unclear native failure: %s", got)
		}
	}
	cancelled := false
	output := cappedOutput{limit: 4, cancel: func() { cancelled = true }}
	if _, e := output.Write([]byte("12345")); e == nil || !output.overflow || !cancelled || output.b.Len() != 0 {
		t.Fatal("native output budget did not stop collection")
	}
}

func TestInterpreterOptionsCannotBecomeFakeScriptPaths(t *testing.T) {
	paths, e := executionPathsAt("{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -W ignore /opt/app/job.py ; ignore_errors=no ; pid=0 }", "/opt/app")
	if e != nil || !slices.Contains(paths, "/opt/app/job.py") || slices.Contains(paths, "/opt/app/ignore") {
		t.Fatal("option value treated as a script", paths, e)
	}
	for _, argv := range [][]string{{"bash", "-ec", "secret inline command"}, {"python3", "-m", "module"}, {"node", "--require", "secret-module", "/opt/job.js"}} {
		if _, e := interpreterScript(argv); e == nil {
			t.Fatal("unsupported interpreter semantics silently accepted", argv[0])
		}
	}
}

func TestPackageProcessAssociationRechecksEachInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executable")
	if err := os.WriteFile(path, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	queries := 0
	i := inspection{ctx: context.Background(), limit: 8, b: collector.Begin("inspect.packages", "fixture"), c: Collector{Snapshot: &domain.Snapshot{Processes: []domain.Process{
		{Executable: path, ExecutableInode: st.Ino, ExecutableDevice: uint64(st.Dev)},
		{Executable: path, ExecutableInode: st.Ino + 1, ExecutableDevice: uint64(st.Dev)},
	}}}, runner: runnerFunc(func(context.Context, string, ...string) ([]byte, error) {
		queries++
		return []byte("fixture: " + path + "\n"), nil
	})}
	got := i.packageProcesses(true)
	if len(got["fixture"]) != 1 || queries != 1 || len(i.b.Diagnostics) == 0 {
		t.Fatalf("replaced executable was associated: %+v queries=%d diagnostics=%+v", got, queries, i.b.Diagnostics)
	}
}
