package inspection

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/advisory"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"github.com/jasonachkar/lasa/internal/storage"
	"golang.org/x/sys/unix"
)

type InstalledPackage struct{ Name, Version, Source, SourceVersion, Architecture string }

func PackageInventory(raw []byte, debian bool) ([]InstalledPackage, error) {
	var out []InstalledPackage
	seen := map[string]bool{}
	for n, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		var p InstalledPackage
		if debian {
			if len(f) != 6 {
				return nil, fmt.Errorf("package inventory line %d has unexpected fields", n+1)
			}
			if !strings.HasPrefix(f[5], "ii") {
				continue
			}
			p = InstalledPackage{f[0], f[1], f[2], f[3], f[4]}
			if p.Source == "" {
				p.Source = p.Name
			}
			if p.SourceVersion == "" && p.Source == p.Name {
				p.SourceVersion = p.Version
			}
		} else {
			if len(f) != 3 {
				return nil, fmt.Errorf("RPM inventory line %d has unexpected fields", n+1)
			}
			p = InstalledPackage{Name: f[0], Version: f[1], Architecture: f[2]}
		}
		if p.Name == "" || p.Version == "" || strings.ContainsAny(p.Name+p.Version+p.Source+p.Architecture, "\x00\r\n") {
			return nil, fmt.Errorf("malformed package metadata at line %d", n+1)
		}
		key := p.Name + ":" + p.Architecture + ":" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
		if len(out) > 100000 {
			return nil, fmt.Errorf("installed package count exceeds 100000")
		}
	}
	return out, nil
}
func osRelease(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("malformed os-release")
		}
		if slices.Contains([]string{"ID", "VERSION_ID", "VERSION_CODENAME"}, key) {
			out[key] = strings.Trim(v, "\"'")
		}
	}
	if out["ID"] == "" || out["VERSION_ID"] == "" {
		return nil, fmt.Errorf("os-release lacks distribution/version")
	}
	return out, nil
}
func (i *inspection) packages() {
	raw, e := i.read("/usr/lib/os-release")
	if e != nil {
		raw, e = i.read("/etc/os-release")
	}
	if e != nil {
		i.fail("read_distribution", "os-release", e)
		return
	}
	osr, e := osRelease(raw)
	if e != nil {
		i.fail("parse_distribution", "os-release", e)
		return
	}
	debian := osr["ID"] == "debian" || osr["ID"] == "ubuntu"
	distribution := osr["ID"] + ":" + osr["VERSION_ID"]
	if osr["ID"] == "debian" && osr["VERSION_CODENAME"] != "" {
		distribution = "debian:" + osr["VERSION_CODENAME"]
	}
	if _, e := advisory.Compare(distribution, "1", "1"); e != nil {
		i.unsupported(distribution, e.Error())
		return
	}
	if debian {
		raw, e = i.runner.Run(i.ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\t${db:Status-Abbrev}\n")
	} else {
		raw, e = i.runner.Run(i.ctx, "rpm", "--noplugins", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	}
	if e != nil {
		i.fail("read_package_inventory", distribution, e)
		return
	}
	packages, e := PackageInventory(raw, debian)
	if e != nil {
		i.fail("parse_package_inventory", distribution, e)
		return
	}
	inventory := i.asset("package_inventory", distribution)
	i.fact(inventory, "packages.installed_count", fmt.Sprint(len(packages)), "native package database", domain.Observed)
	if i.c.Config.AdvisoryFile == "" {
		i.unsupported(distribution, "package vulnerability matching requires --advisories; use lasa advisories update or import an authenticated vendor-derived database")
		return
	}
	raw, e = storage.Read(i.c.Config.AdvisoryFile, advisory.MaxBytes)
	if e != nil {
		i.fail("read_advisories", i.c.Config.AdvisoryFile, e)
		return
	}
	db, e := advisory.Decode(raw)
	if e != nil {
		i.fail("parse_advisories", i.c.Config.AdvisoryFile, e)
		return
	}
	if e = db.Fresh(time.Now(), i.c.Config.AdvisoryMaxAge); e != nil {
		i.fail("validate_advisory_freshness", i.c.Config.AdvisoryFile, e)
		return
	}
	records := map[string][]advisory.Record{}
	for _, r := range db.Records {
		if r.Distribution == distribution || r.Distribution == osr["ID"]+":"+osr["VERSION_ID"] {
			records[r.Package] = append(records[r.Package], r)
		}
	}
	if len(records) == 0 {
		i.unsupported(distribution, "database contains no advisories for this exact distribution release")
		return
	}
	running := i.packageProcesses(debian)
	for _, p := range packages {
		advisories := append([]advisory.Record(nil), records[p.Name]...)
		if p.Source != "" && p.Source != p.Name {
			advisories = append(advisories, records[p.Source]...)
		}
		if len(advisories) == 0 {
			continue
		}
		if !i.next(p.Name) {
			break
		}
		a := i.asset("installed_package", p.Name+":"+p.Architecture)
		refs := []string{i.fact(a, "packages.installed", fmt.Sprintf("name=%s version=%s architecture=%s source=%s source_version=%s", p.Name, p.Version, p.Architecture, p.Source, p.SourceVersion), "native package database", domain.Observed), i.fact(a, "packages.advisory_source", fmt.Sprintf("%s fetched=%s expires=%s", db.Source, db.FetchedAt.Format(time.RFC3339), db.ExpiresAt.Format(time.RFC3339)), i.c.Config.AdvisoryFile, domain.Observed)}
		affected := false
		state := domain.Observed
		high := false
		for _, r := range advisories {
			if e := i.ctx.Err(); e != nil {
				i.fail("evaluate_package_advisories", p.Name, e)
				state = domain.Unknown
				break
			}
			version := p.Version
			if r.SourcePackage {
				if r.Package != p.Source {
					continue
				}
				version = p.SourceVersion
			} else if r.Package != p.Name {
				continue
			}
			yes, err := advisory.Affected(r.Distribution, version, r)
			if err != nil {
				i.fail("compare_native_package_version", p.Name, err)
				state = domain.Unknown
				continue
			}
			if yes {
				affected = true
				high = high || r.Severity == "high" || r.Severity == "critical"
				refs = append(refs, i.fact(a, "packages.vendor_advisory", fmt.Sprintf("id=%s severity=%s installed=%s fixed=%s distribution=%s", r.ID, r.Severity, version, r.Fixed, r.Distribution), db.Source, domain.Observed))
			}
		}
		exposed := false
		for _, proc := range running[p.Name] {
			refs = append(refs, i.fact(a, "asset.related_subject", proc.ID, "package-owned executable with matching observed inode", domain.Observed))
			for _, socket := range i.c.Snapshot.Sockets {
				if socket.Exposure == domain.Potential && slices.Contains(socket.Owners, proc.ID) {
					exposed = true
					refs = append(refs, i.fact(a, "packages.listener", fmt.Sprintf("%s %s:%d", socket.Protocol, socket.Address, socket.Port), proc.Executable, domain.Observed))
				}
			}
		}
		if affected {
			state = domain.Observed
		}
		i.risk(a, "network.potential", exposed, domain.Observed, refs...)
		i.risk(a, "packages.vulnerable", affected, state, refs...)
		i.risk(a, "packages.exposed_vulnerability", affected && exposed, state, refs...)
		i.risk(a, "packages.high_severity", affected && high, state, refs...)
		i.b.Coverage.Successful++
	}
}
func (i *inspection) packageProcesses(debian bool) map[string][]domain.Process {
	out := map[string][]domain.Process{}
	seen := map[string]string{}
	queries := 0
	for _, p := range i.c.Snapshot.Processes {
		if e := i.ctx.Err(); e != nil {
			i.fail("associate_running_packages", "scan deadline", e)
			break
		}
		path := p.Executable
		if strings.HasSuffix(path, " (deleted)") {
			i.unsupported(path, "running executable was deleted; package identity and restart state remain unknown")
			continue
		}
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			continue
		}
		h, e := linux.Open("/", strings.TrimPrefix(path, "/"), unix.O_PATH|unix.O_NOFOLLOW)
		if e != nil {
			i.fail("pin_package_executable", path, e)
			continue
		}
		var st unix.Stat_t
		e = unix.Fstat(int(h.Fd()), &st)
		h.Close()
		if e != nil || st.Ino != p.ExecutableInode || uint64(st.Dev) != p.ExecutableDevice {
			i.unsupported(path, "running executable identity differs from current filesystem path; restart/replace status needs independent review")
			continue
		}
		pkg, ok := seen[path]
		if !ok {
			if queries >= i.limit {
				i.unsupported("running executable ownership", "package ownership query budget reached")
				break
			}
			queries++
			var raw []byte
			if debian {
				raw, e = i.runner.Run(i.ctx, "dpkg-query", "-S", "--", path)
			} else {
				raw, e = i.runner.Run(i.ctx, "rpm", "--noplugins", "-qf", "--qf", "%{NAME}\n", "--", path)
			}
			if e != nil {
				i.fail("query_executable_package_ownership", path, e)
				seen[path] = ""
				continue
			}
			if debian {
				for _, line := range strings.Split(string(raw), "\n") {
					name, target, ok := strings.Cut(line, ": ")
					if ok && target == path {
						if pkg != "" && pkg != name {
							pkg = ""
							break
						}
						pkg, _, _ = strings.Cut(name, ":")
					}
				}
			} else {
				pkg = strings.TrimSpace(string(raw))
				if strings.Contains(pkg, "\n") {
					pkg = ""
				}
			}
			if pkg == "" {
				i.unsupported(path, "native database returned no unambiguous ownership association")
			}
			seen[path] = pkg
		}
		if pkg != "" {
			out[pkg] = append(out[pkg], p)
		}
	}
	return out
}
