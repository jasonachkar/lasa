package inspection

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jasonachkar/lasa/internal/access"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
)

func (i *inspection) read(path string) ([]byte, error) {
	fs := i.c.FS
	if fs == nil {
		fs = linux.FS{Root: "/", Limit: 1 << 20}
	}
	return fs.Read(strings.TrimPrefix(path, "/"))
}
func (i *inspection) accounts() ([]access.Account, error) {
	p, e := i.read("/etc/passwd")
	if e != nil {
		return nil, e
	}
	g, e := i.read("/etc/group")
	if e != nil {
		return nil, e
	}
	return access.Accounts(p, g)
}
func (i *inspection) access(path string, accounts []access.Account) (access.Result, error) {
	if i.c.CheckAccess != nil {
		return i.c.CheckAccess(i.ctx, path, accounts)
	}
	return access.EvaluatePath(i.ctx, path, accounts)
}
func (i *inspection) accessFacts(a domain.Asset, path string, accounts []access.Account) (bool, domain.State, []string) {
	if !i.next(path) {
		return false, domain.Unknown, nil
	}
	r, e := i.access(path, accounts)
	if e != nil {
		i.fail("evaluate_discretionary_access", path, e)
		return false, domain.Unknown, nil
	}
	if r.Uncertain && len(r.Writers) == 0 {
		i.unsupported(path, "mount identity is unavailable for a discretionary replacement candidate")
		return false, domain.Unknown, nil
	}
	refs := []string{i.fact(a, "access.target", r.Target, path, domain.Observed), i.fact(a, "access.local_writers", r.Summary(), path, domain.Observed)}
	for _, writer := range r.Writers {
		refs = append(refs, i.fact(a, "access.writer_identity", fmt.Sprintf("name=%s uid=%d primary_gid=%d supplementary_gids=%v", writer.Name, writer.UID, writer.GID, writer.Groups), "local identity database", domain.Observed))
	}
	for _, m := range r.Metadata {
		if i.exhausted {
			return false, domain.Unknown, refs
		}
		refs = append(refs, i.fact(a, "access.path_metadata", fmt.Sprintf("path=%s device=%d inode=%d uid=%d gid=%d mode=%#o read_only=%t mount_id=%d acl_entries=%d", m.Path, m.Device, m.Inode, m.UID, m.GID, m.Mode, m.ReadOnly, m.MountID, len(m.ACL)), path, domain.Observed))
		for _, entry := range m.ACL {
			if i.exhausted {
				return false, domain.Unknown, refs
			}
			refs = append(refs, i.fact(a, "access.acl_entry", fmt.Sprintf("path=%s tag=%d id=%d permissions=%#o", m.Path, entry.Tag, entry.ID, entry.Perm), m.Path, domain.Observed))
		}
	}
	for _, p := range r.Paths {
		refs = append(refs, i.fact(a, "access.writable_component", p, path, domain.Observed))
	}
	i.b.Coverage.Successful++
	return len(r.Writers) > 0, domain.Observed, refs
}
func properties(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid systemd property response")
		}
		if _, ok := out[k]; ok {
			return nil, fmt.Errorf("duplicate systemd property %s", k)
		}
		out[k] = v
	}
	return out, nil
}

var commandPath = regexp.MustCompile(`(?:^|\{ )path=(.*?) ; argv\[\]=`)
var commandArgv = regexp.MustCompile(`argv\[\]=(.*?) ; (?:ignore_errors|flags)=`)

func nativeWords(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	quote := rune(0)
	escaped := false
	word := false
	for _, r := range s {
		if escaped {
			switch r {
			case 'n', 'r', 't':
				return nil, fmt.Errorf("unsupported control escape in command metadata")
			default:
				b.WriteRune(r)
			}
			escaped = false
			word = true
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			word = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			word = true
			continue
		}
		if r == ' ' || r == '\t' {
			if word {
				out = append(out, b.String())
				b.Reset()
				word = false
			}
			continue
		}
		b.WriteRune(r)
		word = true
	}
	if escaped || quote != 0 {
		return nil, fmt.Errorf("unterminated command quoting")
	}
	if word {
		out = append(out, b.String())
	}
	return out, nil
}
func executionPaths(value string) ([]string, error) { return executionPathsAt(value, "") }
func executionPathsAt(value, workingDirectory string) ([]string, error) {
	if len(value) > 1<<20 {
		return nil, fmt.Errorf("systemd execution metadata exceeds 1MiB")
	}
	matches := commandPath.FindAllStringSubmatch(value, 129)
	if len(matches) > 128 {
		return nil, fmt.Errorf("systemd execution list exceeds 128 commands")
	}
	if len(matches) == 0 {
		if value == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("unsupported systemd execution metadata format")
	}
	var out []string
	for _, m := range matches {
		p := m[1]
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.Contains(p, "\\") {
			return nil, fmt.Errorf("escaped or noncanonical executable path requires independent review")
		}
		out = append(out, p)
	}
	for _, m := range commandArgv.FindAllStringSubmatch(value, -1) {
		argv, e := nativeWords(m[1])
		if e != nil {
			return out, e
		}
		if len(argv) == 0 {
			continue
		}
		name := filepath.Base(argv[0])
		if !strings.HasPrefix(name, "python") && !slices.Contains([]string{"sh", "bash", "dash", "zsh", "ksh", "perl", "ruby", "node"}, name) {
			continue
		}
		arg, e := interpreterScript(argv)
		if e != nil {
			return out, e
		}
		if arg == "" {
			continue
		}
		if !filepath.IsAbs(arg) {
			if !filepath.IsAbs(workingDirectory) || strings.ContainsAny(arg, "$`\\") {
				return out, fmt.Errorf("relative interpreter script lacks a supported effective working directory")
			}
			arg = filepath.Join(workingDirectory, arg)
		}
		if filepath.Clean(arg) != arg {
			return out, fmt.Errorf("noncanonical interpreter script path")
		}
		out = append(out, arg)

	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
func (i *inspection) systemd() {
	accounts, e := i.accounts()
	if e != nil {
		i.fail("read_local_identities", "/etc/passwd and /etc/group", e)
		return
	}
	raw, e := i.runner.Run(i.ctx, "systemctl", "list-units", "--all", "--type=service", "--output=json", "--no-pager", "--plain")
	if e != nil {
		i.fail("list_services", "systemd manager", e)
		return
	}
	var units []struct {
		Unit string `json:"unit"`
	}
	if e = json.Unmarshal(raw, &units); e != nil {
		i.fail("parse_service_inventory", "systemd manager", fmt.Errorf("invalid systemctl JSON"))
		return
	}
	files, e := i.runner.Run(i.ctx, "systemctl", "list-unit-files", "--type=service", "--state=enabled,enabled-runtime,linked,linked-runtime", "--output=json", "--no-pager")
	if e != nil {
		i.fail("list_enabled_services", "systemd manager", e)
	} else {
		var enabled []struct {
			UnitFile string `json:"unit_file"`
		}
		if json.Unmarshal(files, &enabled) != nil {
			i.fail("parse_enabled_services", "systemd manager", fmt.Errorf("invalid unit-file JSON"))
		} else {
			for _, u := range enabled {
				units = append(units, struct {
					Unit string `json:"unit"`
				}{u.UnitFile})
			}
		}
	}
	names := map[string]bool{}
	for _, u := range units {
		if !strings.HasSuffix(u.Unit, ".service") || strings.HasPrefix(u.Unit, "-") || strings.ContainsAny(u.Unit, "\r\n\x00") {
			i.unsupported("unit name", "malformed service name in manager response")
			continue
		}
		names[u.Unit] = true
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	slices.Sort(ordered)
	keys := "Id,LoadState,ActiveState,UnitFileState,User,Group,DynamicUser,RootDirectory,RootImage,WorkingDirectory,EnvironmentFiles,MainPID,ExecStart,ExecStartPre,ExecStartPost,ExecReload,ExecStop,FragmentPath,DropInPaths,NoNewPrivileges,ProtectSystem,PrivateUsers"
	for _, name := range ordered {
		if !i.next(name) {
			break
		}
		raw, e := i.runner.Run(i.ctx, "systemctl", "show", "--no-pager", "--property="+keys, "--", name)
		if e != nil {
			i.fail("read_effective_service", name, e)
			continue
		}
		p, e := properties(raw)
		if e != nil {
			i.fail("parse_service", name, e)
			continue
		}
		required := true
		for _, key := range strings.Split(keys, ",") {
			if _, ok := p[key]; !ok {
				i.fail("parse_service", name, fmt.Errorf("required effective property %s is absent", key))
				required = false
			}
		}
		if !required {
			continue
		}
		a := i.asset("systemd_service", name)
		var refs []string
		for _, key := range []string{"LoadState", "ActiveState", "UnitFileState", "User", "Group", "DynamicUser", "RootDirectory", "RootImage", "WorkingDirectory", "FragmentPath", "NoNewPrivileges", "ProtectSystem", "PrivateUsers"} {
			if v, ok := p[key]; ok {
				refs = append(refs, i.fact(a, "systemd."+key, v, name, domain.Observed))
			}
		}
		if p["LoadState"] != "loaded" {
			i.unsupported(name, "service was not loaded or changed during inspection")
			continue
		}
		active := p["ActiveState"] == "active" || p["ActiveState"] == "activating" || strings.HasPrefix(p["UnitFileState"], "enabled") || strings.HasPrefix(p["UnitFileState"], "linked")
		root := p["User"] == "" || p["User"] == "root" || p["User"] == "0"
		_, haveUser := p["User"]
		_, haveDynamic := p["DynamicUser"]
		root = root && haveUser && haveDynamic && p["DynamicUser"] == "no"
		if !root {
			for _, key := range []string{"ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop"} {
				if strings.Contains(p[key], "full-privileges") {
					i.unsupported(name, "non-root unit contains a privileged execution prefix; command-level identity requires independent review")
				}
			}
		}
		if p["RootDirectory"] != "" || p["RootImage"] != "" || p["PrivateUsers"] != "no" {
			i.unsupported(name, "alternate root image/directory or user namespace prevents host-path privilege interpretation")
			continue
		}
		state := domain.Observed
		writable := false
		if active && root {
			for _, key := range []string{"ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop"} {
				working := p["WorkingDirectory"]
				if working == "" {
					working = "/"
				}
				paths, e := executionPathsAt(p[key], working)
				if e != nil {
					i.unsupported(name+"/"+key, e.Error())
					state = domain.Unknown
				}
				for _, path := range paths {
					refs = append(refs, i.fact(a, "systemd.execution_path", path, name+"/"+key, domain.Observed))
					yes, st, proof := i.accessFacts(a, path, accounts)
					refs = append(refs, proof...)
					writable = writable || yes
					if st == domain.Unknown && !writable {
						state = domain.Unknown
					}
				}
			}
		}
		if active && root && p["EnvironmentFiles"] != "" {
			paths, e := environmentPaths(p["EnvironmentFiles"])
			if e != nil {
				i.unsupported(name, e.Error())
				state = domain.Unknown
			} else {
				for _, path := range paths {
					refs = append(refs, i.fact(a, "systemd.environment_file", path, name, domain.Observed))
					yes, st, proof := i.accessFacts(a, path, accounts)
					refs = append(refs, proof...)
					writable = writable || yes
					if st == domain.Unknown {
						state = domain.Unknown
					}
				}
			}
		}

		if writable {
			state = domain.Observed
		}
		i.risk(a, "systemd.writable_execution", writable, state, refs...)
		exposed := false
		pid, _ := strconv.Atoi(p["MainPID"])
		for _, proc := range i.c.Snapshot.Processes {
			if proc.PID != pid || proc.Service != name {
				continue
			}
			for _, socket := range i.c.Snapshot.Sockets {
				if socket.Exposure == domain.Potential && slices.Contains(socket.Owners, proc.ID) {
					exposed = true
					refs = append(refs, i.fact(a, "systemd.observed_listener", fmt.Sprintf("%s %s:%d", socket.Protocol, socket.Address, socket.Port), name, domain.Observed))
				}
			}
		}
		i.risk(a, "systemd.exposed_unconfined", active && root && exposed && p["NoNewPrivileges"] == "no" && p["ProtectSystem"] == "no", domain.Observed, refs...)
		i.b.Coverage.Successful++
	}
}
func sshContext(s string) error { return config.ValidateSSHContext(s) }

func sshSettings(raw []byte) (map[string]string, error) {
	keys := []string{"permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "authenticationmethods", "strictmodes", "authorizedkeysfile", "allowtcpforwarding", "gatewayports", "permituserenvironment"}
	p := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if ok && slices.Contains(keys, key) {
			if _, ok := p[key]; ok {
				return nil, fmt.Errorf("duplicate SSH setting %s", key)
			}
			p[key] = strings.TrimSpace(value)
		}
	}
	for _, key := range []string{"permitrootlogin", "passwordauthentication", "authenticationmethods", "strictmodes"} {
		if p[key] == "" {
			return nil, fmt.Errorf("effective SSH output lacks %s", key)
		}
	}
	for _, key := range []string{"passwordauthentication", "strictmodes"} {
		if p[key] != "yes" && p[key] != "no" {
			return nil, fmt.Errorf("unsupported effective SSH value for %s", key)
		}
	}
	if !slices.Contains([]string{"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}, p["permitrootlogin"]) {
		return nil, fmt.Errorf("unsupported effective PermitRootLogin value")
	}
	return p, nil
}
func (i *inspection) ssh() {
	contexts := i.c.Config.SSHContexts
	if len(contexts) == 0 {
		contexts = []string{"user=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22"}
	}
	for _, connection := range contexts {
		if !i.next("sshd context") {
			break
		}
		if e := sshContext(connection); e != nil {
			i.fail("validate_ssh_context", "--ssh-context", e)
			continue
		}
		// -G parses effective configuration without -T's host-key sanity checks.
		raw, e := i.runner.Run(i.ctx, "sshd", "-G", "-C", connection)
		if e != nil {
			i.fail("read_effective_ssh", "sshd -G (OpenSSH 9.3+; no private-key validation)", e)
			continue
		}
		p, e := sshSettings(raw)
		if e != nil {
			i.fail("parse_effective_ssh", "sshd -G", e)
			continue
		}
		a := i.asset("ssh_policy", connection)
		refs := []string{i.fact(a, "ssh.connection_context", connection, "sshd -G -C", domain.Observed)}
		keys := make([]string, 0, len(p))
		for k := range p {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			refs = append(refs, i.fact(a, "ssh."+k, p[k], "sshd -G -C", domain.Observed))
		}
		passwordOnly := p["authenticationmethods"] == "any"
		for _, alternative := range strings.Fields(p["authenticationmethods"]) {
			passwordOnly = passwordOnly || alternative == "password"
		}
		rootContext := strings.HasPrefix(connection, "user=root,") || strings.Contains(","+connection+",", ",user=root,")
		i.risk(a, "ssh.root_password", rootContext && p["permitrootlogin"] == "yes" && p["passwordauthentication"] == "yes" && passwordOnly, domain.Observed, refs...)
		i.risk(a, "ssh.strict_modes_disabled", p["strictmodes"] == "no", domain.Observed, refs...)
		i.b.Coverage.Successful++
	}
}

type sudoGrant struct {
	Root, All, NoPassword             bool
	hasRunAs, hasCommands, exclusions bool
	Commands                          []string
}

func sudoGrants(raw []byte) ([]sudoGrant, error) {
	var grants []sudoGrant
	var g *sudoGrant
	commands := false
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "Sudoers entry:" {
			grants = append(grants, sudoGrant{})
			g = &grants[len(grants)-1]
			commands = false
			continue
		}
		if g == nil {
			continue
		}
		if strings.HasPrefix(s, "RunAsUsers:") {
			g.hasRunAs = true
			v := strings.TrimSpace(strings.TrimPrefix(s, "RunAsUsers:"))
			for _, u := range strings.Split(v, ",") {
				u = strings.TrimSpace(u)
				switch u {
				case "root", "ALL", "#0":
					g.Root = true
				case "!root", "!ALL", "!#0":
					g.Root = false
				default:
					if strings.ContainsAny(u, "%+*") || strings.ToUpper(u) == u {
						return nil, fmt.Errorf("unresolved RunAs expression requires independent review")
					}
				}
			}
			continue
		}
		if strings.HasPrefix(s, "Options:") {
			v := strings.TrimPrefix(s, "Options:")
			for _, o := range strings.Split(v, ",") {
				if strings.TrimSpace(o) == "authenticate" {
					g.NoPassword = false
				}
				if strings.TrimSpace(o) == "!authenticate" {
					g.NoPassword = true
				}
			}
			continue
		}
		if s == "Commands:" {
			commands = true
			g.hasCommands = true
			continue
		}
		if commands && s != "" {
			if strings.HasPrefix(s, "!") {
				g.exclusions = true
				continue
			}
			if s == "ALL" {
				g.All = true
			} else {
				words, e := nativeWords(s)
				if e != nil {
					return nil, e
				}
				if len(words) > 0 && filepath.IsAbs(words[0]) {
					g.Commands = append(g.Commands, words[0])
				} else {
					return nil, fmt.Errorf("unsupported sudo command expression")
				}
			}
		}
	}
	for n := range grants {
		if !grants[n].hasRunAs || !grants[n].hasCommands {
			return nil, fmt.Errorf("sudo entry lacks required RunAs or Commands metadata")
		}
		if grants[n].exclusions {
			grants[n].All = false
		}
		if len(grants[n].Commands) > 256 {
			return nil, fmt.Errorf("sudo entry exceeds 256 command paths")
		}
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf("sudo did not return supported long-list policy entries")
	}
	return grants, nil
}
func (i *inspection) sudo() {
	accounts, e := i.accounts()
	if e != nil {
		i.fail("read_local_identities", "local account database", e)
		return
	}
	for _, account := range accounts {
		if account.UID == 0 {
			continue
		}
		if !i.next(account.Name) {
			break
		}
		raw, e := i.runner.Run(i.ctx, "sudo", "-n", "-ll", "-U", account.Name)
		if e != nil {
			i.fail("query_effective_sudo_policy", account.Name, e)
			continue
		}
		grants, e := sudoGrants(raw)
		if e != nil {
			i.fail("parse_effective_sudo_policy", account.Name, e)
			continue
		}
		a := i.asset("sudo_identity", account.Name)
		refs := []string{i.fact(a, "identity.local_account", fmt.Sprintf("%s uid=%d gid=%d", account.Name, account.UID, account.GID), "/etc/passwd and /etc/group", domain.Observed)}
		all, noPassword, writable := false, false, false
		state := domain.Observed
		for _, grant := range grants {
			if !grant.Root {
				continue
			}
			all = all || grant.All
			noPassword = noPassword || grant.All && grant.NoPassword
			for _, path := range grant.Commands {
				refs = append(refs, i.fact(a, "sudo.root_command", path, "sudo -n -ll -U", domain.Observed))
				yes, st, proof := i.accessFacts(a, path, []access.Account{account})
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
		i.risk(a, "sudo.unrestricted_root", all, domain.Observed, refs...)
		i.risk(a, "sudo.passwordless_root", noPassword, domain.Observed, refs...)
		i.risk(a, "sudo.writable_command", writable, state, refs...)
		i.b.Coverage.Successful++
	}
}
func (i *inspection) permissions() {
	accounts, e := i.accounts()
	if e != nil {
		i.fail("read_local_identities", "local account database", e)
		return
	}
	for _, file := range i.c.Snapshot.Files {
		priv := file.Mode&06000 != 0 || file.Capabilities != ""
		for _, p := range i.c.Snapshot.Processes {
			if p.Identity.UID[1] == 0 && p.Namespaces["user"] == "user:[4026531837]" && p.ExecutableDevice == file.Device && p.ExecutableInode == file.Inode {
				priv = true
			}
		}
		if !priv && !slices.Contains([]string{"service_config", "sudoers", "authorized_keys", "runtime_socket"}, file.Kind) {
			continue
		}
		if !i.next(file.Path) {
			break
		}
		a := i.asset("permission_path", file.Path)
		refs := []string{i.fact(a, "access.target_kind", file.Kind, file.Path, domain.Observed)}
		yes, state, proof := i.accessFacts(a, file.Path, accounts)
		refs = append(refs, proof...)
		i.risk(a, "permissions.privileged_write", yes, state, refs...)
		i.b.Coverage.Successful++
	}
}

var environmentFilePattern = regexp.MustCompile(`^(/[^ \t\r\n\\]+) \(ignore_errors=(?:yes|no)\)(?: |$)`)

func environmentPaths(value string) ([]string, error) {
	var out []string
	for strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		match := environmentFilePattern.FindStringSubmatchIndex(value)
		if match == nil {
			return nil, fmt.Errorf("escaped or unsupported systemd environment-file metadata")
		}
		path := value[match[2]:match[3]]
		if filepath.Clean(path) != path {
			return nil, fmt.Errorf("noncanonical environment-file path")
		}
		out = append(out, path)
		if len(out) > 128 {
			return nil, fmt.Errorf("environment-file list exceeds 128 paths")
		}
		value = value[match[1]:]
	}
	return out, nil
}

func interpreterScript(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", nil
	}
	name := filepath.Base(argv[0])
	shell := slices.Contains([]string{"sh", "bash", "dash", "zsh", "ksh"}, name)
	python := strings.HasPrefix(name, "python")
	stopOptions := false
	for n := 1; n < len(argv); n++ {
		arg := argv[n]
		if !stopOptions && arg == "--" {
			stopOptions = true
			continue
		}
		if !stopOptions && strings.HasPrefix(arg, "-") {
			if arg == "-" {
				return "", fmt.Errorf("interpreter reads a program from stdin")
			}
			if python {
				if arg == "-W" || arg == "--check-hash-based-pycs" {
					n++
					if n >= len(argv) {
						return "", fmt.Errorf("interpreter option is missing its value")
					}
					continue
				}
				if strings.HasPrefix(arg, "-W") || slices.Contains([]string{"-I", "-E", "-B", "-s", "-S", "-u", "-q", "-O", "-OO"}, arg) {
					continue
				}
				return "", fmt.Errorf("unsupported or inline Python execution option")
			}
			if shell {
				if arg == "-o" || arg == "-O" {
					n++
					if n >= len(argv) {
						return "", fmt.Errorf("shell option is missing its value")
					}
					continue
				}
				safe := strings.TrimPrefix(arg, "-")
				if safe != "" && strings.Trim(safe, "euxfBCEHT") == "" {
					continue
				}
				return "", fmt.Errorf("interactive, inline, startup-file or unsupported shell option")
			}
			return "", fmt.Errorf("unsupported interpreter option requires independent review")
		}
		return arg, nil
	}
	return "", fmt.Errorf("interpreter has no statically selected script")
}
