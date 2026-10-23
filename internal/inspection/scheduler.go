package inspection

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jasonachkar/lasa/internal/access"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

type CronJob struct {
	Line        int
	CommandName string
	User        string
	Paths       []string
	Search      []string
}

var cronField = regexp.MustCompile(`^[A-Za-z0-9*/?,\-]+$`)
var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*\s*=`)

func ParseCron(raw []byte, owner string) ([]CronJob, error) {
	var out []CronJob
	var failures []error
	search := []string{"/usr/bin", "/bin"}
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if envAssignment.MatchString(line) {
			key, value, _ := strings.Cut(line, "=")
			key = strings.TrimSpace(key)
			if key == "PATH" {
				value = strings.Trim(strings.TrimSpace(value), "\"'")
				candidate := strings.Split(value, ":")
				valid := true
				for _, p := range candidate {
					if !filepath.IsAbs(p) || filepath.Clean(p) != p {
						valid = false
					}
				}
				if valid {
					search = candidate
				} else {
					failures = append(failures, fmt.Errorf("cron line %d: relative or empty PATH component", n+1))
					search = nil
				}
			}
			if slices.Contains([]string{"LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "PYTHONPATH", "PERL5OPT", "NODE_OPTIONS"}, key) {
				failures = append(failures, fmt.Errorf("cron line %d: execution-altering environment setting requires independent review", n+1))
			}
			continue
		}
		job, e := cronRecord(line, owner, search)
		if e != nil {
			if len(failures) < 128 {
				failures = append(failures, fmt.Errorf("cron line %d: %w", n+1, e))
			}
			continue
		}
		job.Line = n + 1
		out = append(out, job)
		if len(out) >= 4096 {
			failures = append(failures, fmt.Errorf("cron file exceeds 4096-job budget"))
			break
		}
	}
	return out, errors.Join(failures...)
}
func cronRecord(line, owner string, search []string) (CronJob, error) {
	job := CronJob{}
	fields := strings.Fields(line)
	start := 5
	if strings.HasPrefix(line, "@") {
		if len(fields) < 2 || !slices.Contains([]string{"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}, fields[0]) {
			return job, fmt.Errorf("unsupported schedule")
		}
		start = 1
	} else {
		if len(fields) < 6 {
			return job, fmt.Errorf("incomplete schedule")
		}
		for _, field := range fields[:5] {
			if !cronField.MatchString(field) {
				return job, fmt.Errorf("unsupported schedule field")
			}
		}
	}
	job.User = owner
	if owner == "" {
		if len(fields) <= start+1 {
			return job, fmt.Errorf("missing user or command")
		}
		job.User = fields[start]
		start++
	}
	if len(fields) <= start {
		return job, fmt.Errorf("missing command")
	}
	command := strings.Join(fields[start:], " ")
	if strings.ContainsAny(command, "|&;`$<>%\n\r") {
		return job, fmt.Errorf("shell expansion, pipeline or control flow requires independent review")
	}
	argv, e := nativeWords(command)
	if e != nil || len(argv) == 0 {
		return job, fmt.Errorf("unsupported command quoting")
	}
	name := filepath.Base(argv[0])
	if slices.Contains([]string{"env", "su", "sudo", "runuser", "chroot", "nice", "ionice", "timeout", "setsid"}, name) {
		return job, fmt.Errorf("execution wrapper requires independent review")
	}
	if filepath.IsAbs(argv[0]) {
		job.Paths = append(job.Paths, argv[0])
	} else {
		if strings.Contains(argv[0], "/") {
			return job, fmt.Errorf("relative executable path")
		}
		if len(search) == 0 {
			return job, fmt.Errorf("executable search PATH is unresolved")
		}
		job.Search = append(job.Search, search...)
		job.CommandName = argv[0]
	}
	if slices.Contains([]string{"sh", "bash", "dash", "python", "python3", "perl", "ruby", "node"}, name) {
		arg, e := interpreterScript(argv)
		if e != nil {
			return job, e
		}
		if !filepath.IsAbs(arg) {
			return job, fmt.Errorf("relative interpreter script requires independent review")
		}
		job.Paths = append(job.Paths, arg)

	}
	return job, nil
}

func (i *inspection) scheduler() {
	accounts, e := i.accounts()
	if e != nil {
		i.fail("read_local_identities", "local account database", e)
		return
	}
	fs := i.c.FS
	if fs == nil {
		fs = linux.FS{Root: "/", Limit: 1 << 20}
	}
	paths := []string{"/etc/crontab", "/var/spool/cron/crontabs/root", "/var/spool/cron/root"}
	names, cut, e := fs.Names("etc/cron.d", i.limit)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		i.fail("list_cron", "/etc/cron.d", e)
	} else {
		if cut {
			i.unsupported("/etc/cron.d", "directory exceeds inspection budget")
		}
		slices.Sort(names)
		valid := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
		for _, name := range names {
			if valid.MatchString(name) {
				paths = append(paths, "/etc/cron.d/"+name)
			}
		}
	}
	for _, path := range paths {
		if !i.next(path) {
			break
		}
		raw, e := i.read(path)
		if errors.Is(e, os.ErrNotExist) {
			i.b.Coverage.Successful++
			continue
		}
		if e != nil {
			i.fail("read_cron", path, e)
			continue
		}
		owner := ""
		if strings.HasPrefix(path, "/var/spool/") {
			owner = "root"
		}
		jobs, e := ParseCron(raw, owner)
		if e != nil {
			i.unsupported(path, e.Error())
		}
		for _, job := range jobs {
			if !i.next(fmt.Sprintf("%s:%d", path, job.Line)) {
				break
			}
			root := job.User == "root"
			for _, account := range accounts {
				if account.Name == job.User && account.UID == 0 {
					root = true
				}
			}
			if !root {
				continue
			}
			a := i.asset("scheduled_job", fmt.Sprintf("%s:%d", path, job.Line))
			refs := []string{i.fact(a, "scheduler.identity", job.User, path, domain.Observed)}
			writable, state, proof := i.accessFacts(a, path, accounts)
			refs = append(refs, proof...)
			for _, target := range job.Paths {
				yes, st, proof := i.accessFacts(a, target, accounts)
				refs = append(refs, proof...)
				writable = writable || yes
				if st == domain.Unknown {
					state = domain.Unknown
				}
			}
			if len(job.Search) > 0 {
				yes, st, proof := i.cronSearch(a, job.Search, job.CommandName, accounts)
				refs = append(refs, proof...)
				writable = writable || yes
				if st == domain.Unknown {
					state = domain.Unknown
				}
			}
			if writable {
				state = domain.Observed
			}
			i.risk(a, "scheduler.writable_root_job", writable, state, refs...)
		}
		i.b.Coverage.Successful++
	}
	i.timers(accounts)
}
func (i *inspection) timers(accounts []access.Account) {
	raw, e := i.runner.Run(i.ctx, "systemctl", "list-units", "--all", "--type=timer", "--output=json", "--no-pager")
	if e != nil {
		i.fail("list_timers", "systemd manager", e)
		return
	}
	var units []struct {
		Unit string `json:"unit"`
	}
	if json.Unmarshal(raw, &units) != nil {
		i.fail("parse_timers", "systemd manager", fmt.Errorf("invalid timer inventory JSON"))
		return
	}
	for _, u := range units {
		if !strings.HasSuffix(u.Unit, ".timer") || strings.HasPrefix(u.Unit, "-") {
			i.unsupported("timer", "invalid timer name")
			continue
		}
		if !i.next(u.Unit) {
			break
		}
		raw, e := i.runner.Run(i.ctx, "systemctl", "show", "--property=ActiveState,Triggers", "--no-pager", "--", u.Unit)
		if e != nil {
			i.fail("read_timer", u.Unit, e)
			continue
		}
		timer, e := properties(raw)
		if e != nil {
			i.fail("parse_timer", u.Unit, e)
			continue
		}
		if _, ok := timer["ActiveState"]; !ok {
			i.fail("parse_timer", u.Unit, fmt.Errorf("required effective property ActiveState is absent"))
			continue
		}
		if _, ok := timer["Triggers"]; !ok {
			i.fail("parse_timer", u.Unit, fmt.Errorf("required effective property Triggers is absent"))
			continue
		}
		if timer["ActiveState"] != "active" {
			i.b.Coverage.Successful++
			continue
		}
		for _, unit := range strings.Fields(timer["Triggers"]) {
			if !i.next(unit) {
				break
			}
			if !strings.HasSuffix(unit, ".service") || strings.HasPrefix(unit, "-") {
				i.unsupported(u.Unit, "timer trigger is not a supported service")
				continue
			}
			raw, e := i.runner.Run(i.ctx, "systemctl", "show", "--property=User,DynamicUser,RootDirectory,RootImage,PrivateUsers,ExecStart,ExecStartPre", "--no-pager", "--", unit)
			if e != nil {
				i.fail("read_timer_service", unit, e)
				continue
			}
			p, e := properties(raw)
			if e != nil {
				i.fail("parse_timer_service", unit, e)
				continue
			}
			valid := true
			for _, key := range strings.Split("User,DynamicUser,RootDirectory,RootImage,PrivateUsers,ExecStart,ExecStartPre", ",") {
				if _, ok := p[key]; !ok {
					i.fail("parse_timer_service", unit, fmt.Errorf("required effective property %s is absent", key))
					valid = false
				}
			}
			if !valid {
				continue
			}
			if p["User"] != "" && p["User"] != "root" && p["User"] != "0" || p["DynamicUser"] != "no" {
				continue
			}
			if p["RootDirectory"] != "" || p["RootImage"] != "" || p["PrivateUsers"] != "no" {
				i.unsupported(unit, "alternate filesystem/user namespace prevents path interpretation")
				continue
			}
			a := i.asset("systemd_timer", u.Unit+" -> "+unit)
			var refs []string
			writable := false
			state := domain.Observed
			for _, key := range []string{"ExecStartPre", "ExecStart"} {
				paths, e := executionPaths(p[key])
				if e != nil {
					i.unsupported(unit, e.Error())
					state = domain.Unknown
				}
				for _, path := range paths {
					yes, st, proof := i.accessFacts(a, path, accounts)
					refs = append(refs, proof...)
					writable = writable || yes
					if st == domain.Unknown {
						state = domain.Unknown
					}
				}
			}
			if writable {
				state = domain.Observed
			}
			i.risk(a, "scheduler.writable_root_job", writable, state, refs...)
		}
		i.b.Coverage.Successful++
	}
}

func (i *inspection) cronSearch(a domain.Asset, dirs []string, name string, accounts []access.Account) (bool, domain.State, []string) {
	var refs []string
	writable := false
	state := domain.Observed
	for _, dir := range dirs {
		path := filepath.Join(dir, name)
		if !i.next(path) {
			return writable, domain.Unknown, refs
		}
		r, e := i.access(path, accounts)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			i.fail("resolve_cron_executable", path, e)
			state = domain.Unknown
			continue
		}
		if e != nil {
			yes, st, proof := i.accessFacts(a, dir, accounts)
			refs = append(refs, proof...)
			writable = writable || yes
			if st == domain.Unknown {
				state = domain.Unknown
			}
			continue
		}
		for _, m := range r.Metadata {
			if m.Path == r.Target && m.Mode&0111 != 0 {
				refs = append(refs, i.fact(a, "scheduler.resolved_executable", r.Target, a.Label, domain.Observed))
				yes, st, proof := i.accessFacts(a, path, accounts)
				refs = append(refs, proof...)
				writable = writable || yes
				if st == domain.Unknown {
					state = domain.Unknown
				}
				return writable, state, refs
			}
		}
		yes, st, proof := i.accessFacts(a, dir, accounts)
		refs = append(refs, proof...)
		writable = writable || yes
		if st == domain.Unknown {
			state = domain.Unknown
		}
	}
	i.unsupported(a.Label, "cron command did not resolve to a supported executable in its explicit PATH")
	return writable, domain.Unknown, refs
}
