package inspection

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
)

func TestCronJobsAndUnsupportedShellExpressions(t *testing.T) {
	raw := []byte("SECRET=do-not-store\nPATH=/usr/bin:/bin\n0 * * * * root /usr/bin/bash /opt/backup.sh SECRET_ARGUMENT\n@reboot root /opt/startup\n")
	jobs, e := ParseCron(raw, "")
	if e != nil || len(jobs) != 2 || jobs[0].User != "root" || len(jobs[0].Paths) != 2 || jobs[0].Paths[1] != "/opt/backup.sh" {
		t.Fatalf("%+v %v", jobs, e)
	}
	for _, s := range []string{"* * * * * root curl x | sh", "* * * * * root /bin/sh -c run", "PATH=:/usr/bin\n* * * * * root /usr/bin/id", "* * * * * root ../job"} {
		if _, e := ParseCron([]byte(s), ""); e == nil {
			t.Fatal("unsupported cron command silently accepted", s)
		}
	}
}
func TestSchedulerWritableInterpreterScript(t *testing.T) {
	fs := identities()
	fs["etc/crontab"] = "* * * * * root /usr/bin/bash /opt/backup.sh PRIVATE_ARGUMENT\n"
	b := (Collector{Module: "scheduler", Config: config.Default(), Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, FS: fs, CheckAccess: fixtureAccess("/opt/backup.sh"), Runner: runnerFunc(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, errors.New("no systemd manager in cron-only fixture")
	})}).Collect(context.Background())
	if !hasRisk(b, "scheduler.writable_root_job", "true") {
		t.Fatal("privileged script write path missed", b)
	}
	for _, o := range b.Observations {
		if strings.Contains(o.Value, "PRIVATE_ARGUMENT") {
			t.Fatal("cron argument retained")
		}
	}
}

func TestUnsupportedCronLineDoesNotHideLaterJobs(t *testing.T) {
	jobs, e := ParseCron([]byte("* * * * * root curl x | sh\n@reboot root /opt/later-job\n"), "")
	if e == nil || len(jobs) != 1 || jobs[0].Paths[0] != "/opt/later-job" {
		t.Fatalf("later independent job was lost: %+v %v", jobs, e)
	}
}

func TestTimerMissingEffectivePropertiesRemainUnknown(t *testing.T) {
	for _, missing := range []string{"ActiveState", "Triggers", "User", "ExecStart"} {
		t.Run(missing, func(t *testing.T) {
			runner := runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "list-units" {
					return []byte(`[{"unit":"example.timer"}]`), nil
				}
				response := "ActiveState=active\nTriggers=example.service\n"
				if args[len(args)-1] == "example.service" {
					response = "User=root\nDynamicUser=no\nRootDirectory=\nRootImage=\nPrivateUsers=no\nExecStart={ path=/opt/job ; argv[]=/opt/job ; ignore_errors=no }\nExecStartPre=\n"
				}
				lines := strings.Split(response, "\n")
				var kept []string
				for _, line := range lines {
					if !strings.HasPrefix(line, missing+"=") {
						kept = append(kept, line)
					}
				}
				return []byte(strings.Join(kept, "\n")), nil
			})
			b := (Collector{Module: "scheduler", Config: config.Default(), Snapshot: &domain.Snapshot{Host: domain.Host{ID: "h"}}, FS: identities(), Runner: runner, CheckAccess: fixtureAccess("")}).Collect(context.Background())
			if b.Coverage.Complete || len(b.Diagnostics) == 0 || hasRisk(b, "scheduler.writable_root_job", "false") {
				t.Fatalf("missing %s treated as negative: %+v", missing, b)
			}
		})
	}
}
