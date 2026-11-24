// Package filesystem reads bounded metadata, never application file contents.
package filesystem

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"golang.org/x/sys/unix"
)

type Collector struct {
	Config config.Config
	HostID string
}

func (c Collector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "filesystem", Version: "1", Features: []string{"openat2", "stat", "xattr"}, OptionalPrivileges: []string{"directory search permission for explicitly scoped sensitive paths"}}
}
func (c Collector) Collect(ctx context.Context) (b domain.Batch) {
	b = collector.Begin("filesystem", "metadata only; configured roots, at most two directory levels, bounded entry budget; no symlinks")
	defer collector.Finish(&b)
	type item struct {
		path  string
		depth int
	}
	var queue []item
	for _, r := range c.Config.Roots {
		queue = append(queue, item{r, 0})
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		if e := ctx.Err(); e != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "collect", "configured roots", e))
			b.Coverage.Inconclusive++
			break
		}
		it := queue[0]
		queue = queue[1:]
		if seen[it.path] {
			continue
		}
		seen[it.path] = true
		if b.Coverage.Attempted >= c.Config.MaxFiles {
			b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("filesystem", "metadata entries"))
			b.Coverage.Skipped += len(queue) + 1
			break
		}
		b.Coverage.Attempted++
		h, e := linux.Open("/", strings.TrimPrefix(it.path, "/"), unix.O_PATH|unix.O_NOFOLLOW)
		if e != nil {
			switch {
			case it.depth == 0 && errors.Is(e, unix.ENOENT):
				// A configured root that does not exist is an established
				// absence, not a visibility gap (for example /run/docker.sock
				// on a host without Docker).
				b.Diagnostics = append(b.Diagnostics, diagnostics.Expected(diagnostics.CodeNotPresent, "filesystem", "open_metadata", it.path,
					"configured root does not exist in this mount namespace",
					"Nothing exists at this path to inspect; no rule can match it.",
					"No action is needed unless the path is expected to exist; check the spelling of explicit --roots."))
				b.Coverage.Unsupported++
			case errors.Is(e, unix.ELOOP):
				d := diagnostics.New("filesystem", "open_metadata", it.path, e)
				d.Cause = "path traverses a symbolic link; LASA never follows symbolic links"
				d.Remediation = "Use the canonical path (for example the output of realpath) as an explicit root."
				b.Diagnostics = append(b.Diagnostics, d)
				b.Coverage.Inconclusive++
			default:
				b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "open_metadata", it.path, e))
				b.Coverage.Inconclusive++
			}
			continue
		}
		var st unix.Stat_t
		e = unix.Fstat(int(h.Fd()), &st)
		if e != nil {
			_ = h.Close()
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "stat", it.path, e))
			b.Coverage.Inconclusive++
			continue
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = h.Close()
			cause := "symbolic link; links are not followed by policy"
			if target, le := (linux.FS{Root: "/"}).Readlink(strings.TrimPrefix(it.path, "/")); le == nil {
				cause = "symbolic link to " + target + "; links are not followed by policy"
			}
			b.Diagnostics = append(b.Diagnostics, diagnostics.Expected(diagnostics.CodeSymlinkNotFollowed, "filesystem", "inspect", it.path, cause,
				"The link is recorded as excluded; its target is not inspected through this path.",
				"Add the canonical target path to --roots if it is relevant to the review."))
			b.Coverage.Unsupported++
			continue
		}
		f := domain.File{ID: domain.Hash(c.HostID, it.path), Path: it.path, Inode: st.Ino, Device: uint64(st.Dev), Mode: st.Mode, UID: st.Uid, GID: st.Gid, ACL: domain.Unknown, ReadOnly: domain.Unknown, Kind: kind(it.path, st.Mode)}
		var mountStat unix.Statfs_t
		if e := unix.Fstatfs(int(h.Fd()), &mountStat); e != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "statfs", it.path, e))
			b.Coverage.Inconclusive++
		} else {
			f.ReadOnly = domain.NotObserved
			if mountStat.Flags&unix.ST_RDONLY != 0 {
				f.ReadOnly = domain.Observed
			}
		}

		// getxattr through our own pinned O_PATH descriptor avoids opening a device
		// substituted between stat and open. This proc link is scanner-controlled.
		capState := domain.Unknown
		capEnabled := false
		if st.Mode&unix.S_IFMT == unix.S_IFREG || st.Mode&unix.S_IFMT == unix.S_IFDIR {
			fdPath := fmt.Sprintf("/proc/self/fd/%d", h.Fd())
			buf := make([]byte, 4096)
			n, xe := unix.Getxattr(fdPath, "system.posix_acl_access", buf)
			switch {
			case xe == nil && n > 0:
				f.ACL = domain.Observed
			case errors.Is(xe, unix.ENODATA), errors.Is(xe, unix.EOPNOTSUPP):
				f.ACL = domain.NotObserved
			default:
				if xe == nil {
					xe = fmt.Errorf("empty ACL metadata")
				}
				b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "read_acl_metadata", it.path, xe))
				b.Coverage.Inconclusive++
			}
			n, xe = unix.Getxattr(fdPath, "security.capability", buf)
			switch {
			case xe == nil:
				var parseErr error
				capEnabled, parseErr = CapabilitiesEnabled(buf[:n])
				if parseErr != nil {
					b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "parse_file_capabilities", it.path, parseErr))
					b.Coverage.Inconclusive++
				} else {
					f.Capabilities = hex.EncodeToString(buf[:n])
					capState = domain.Observed
				}
			case errors.Is(xe, unix.ENODATA), errors.Is(xe, unix.EOPNOTSUPP):
				capState = domain.Observed
			default:
				b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "read_capability_metadata", it.path, xe))
				b.Coverage.Inconclusive++
			}
		} else {
			capState = domain.NotApplicable
		}
		if e := h.Close(); e != nil {
			b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "close_metadata", it.path, e))
			b.Coverage.Inconclusive++
		}

		if !utf8.ValidString(f.Path) {
			b.Diagnostics = append(b.Diagnostics, domain.Diagnostic{Code: "METADATA_ENCODING", Component: "filesystem", Operation: "encode_path", Target: strconv.QuoteToASCII(f.Path), Cause: "Non-UTF-8 path bytes; JSON display labels are lossy, while identifiers use original bytes.", Impact: "Use the quoted target for exact path identification; do not assume display labels are unique.", Remediation: "Inspect the quoted byte path using an appropriate native filesystem tool.", Recoverable: true})
			b.Coverage.Inconclusive++
		}
		b.Files = append(b.Files, f)
		b.Coverage.Successful++
		at := time.Now().UTC()
		fact := func(key, value string, state domain.State) {
			b.Observations = append(b.Observations, domain.Fact(f.ID, key, value, it.path, "filesystem", state, at))
		}
		fact("file.metadata", fmt.Sprintf("mode=%#o uid=%d gid=%d inode=%d device=%d", f.Mode, f.UID, f.GID, f.Inode, f.Device), domain.Observed)
		fact("file.kind", f.Kind, domain.Observed)
		fact("file.search_path", strconv.FormatBool(it.path == "/usr/bin" || it.path == "/usr/sbin" || it.path == "/usr/local/bin" || it.path == "/usr/local/sbin"), domain.Observed)
		fact("file.owner_root", strconv.FormatBool(f.UID == 0), domain.Observed)
		fact("file.executable", strconv.FormatBool(st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0111 != 0), domain.Observed)
		fact("file.sgid", strconv.FormatBool(st.Mode&unix.S_ISGID != 0), domain.Observed)
		fact("file.suid", strconv.FormatBool(st.Mode&unix.S_ISUID != 0), domain.Observed)
		fact("file.capability", strconv.FormatBool(capEnabled), capState)
		potentialWrite := (f.Mode&0002 != 0 || f.Mode&0020 != 0 && f.GID != 0) && f.ReadOnly != domain.Observed
		fact("file.write_candidate", strconv.FormatBool(potentialWrite), domain.Observed)
		fact("file.acl_present", strconv.FormatBool(f.ACL == domain.Observed), func() domain.State {
			if f.ACL == domain.Unknown {
				return domain.Unknown
			}
			return domain.Observed
		}())
		fact("file.readonly", strconv.FormatBool(f.ReadOnly == domain.Observed), func() domain.State {
			if f.ReadOnly == domain.Unknown {
				return domain.Unknown
			}
			return domain.Observed
		}())
		if st.Mode&unix.S_IFMT == unix.S_IFDIR && it.depth < 2 {
			remaining := c.Config.MaxFiles - b.Coverage.Attempted - len(queue)
			if remaining < 1 {
				b.Coverage.Skipped++
				b.Coverage.Complete = false
				continue
			}
			reader := linux.FS{Root: "/"}
			names, cut, e := reader.Names(strings.TrimPrefix(it.path, "/"), remaining)
			if e != nil {
				b.Diagnostics = append(b.Diagnostics, diagnostics.New("filesystem", "enumerate", it.path, e))
				b.Coverage.Inconclusive++
				continue
			}
			if cut {
				b.Diagnostics = append(b.Diagnostics, diagnostics.Limit("filesystem", it.path))
				b.Coverage.Skipped++
			}
			sort.Strings(names)
			for _, name := range names {
				queue = append(queue, item{filepath.Join(it.path, name), it.depth + 1})
			}
		}
	}
	return
}

// unitDirectories are systemd unit search paths. Matching them as path
// segments also recognizes the same layout inside a mounted image or
// container root filesystem that is explicitly scoped.
var unitDirectories = []string{"/etc/systemd/system/", "/run/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/", "/usr/local/lib/systemd/system/"}

// kind classifies a path by where the consuming program looks for it, not by
// its name alone: a file named sudoers in an arbitrary directory is never
// read by sudo and must not be reported as sudoers configuration.
func kind(path string, mode uint32) string {
	regular := mode&unix.S_IFMT == unix.S_IFREG
	switch {
	case regular && isSudoers(path):
		return "sudoers"
	case regular && filepath.Base(filepath.Dir(path)) == ".ssh" && (filepath.Base(path) == "authorized_keys" || filepath.Base(path) == "authorized_keys2"):
		return "authorized_keys"
	case regular && isUnitConfiguration(path):
		return "service_config"
	case mode&unix.S_IFMT == unix.S_IFSOCK && (strings.HasSuffix(path, "/docker.sock") || strings.HasSuffix(path, "/containerd.sock") || strings.HasSuffix(path, "/crio.sock") || strings.HasSuffix(path, "/podman.sock")):
		return "runtime_socket"
	case mode&unix.S_IFMT == unix.S_IFDIR:
		return "directory"
	case mode&0111 != 0 && regular:
		return "executable"
	}
	return "other"
}

func isSudoers(path string) bool {
	if path == "/etc/sudoers" || strings.HasSuffix(path, "/etc/sudoers") {
		return true
	}
	dir := filepath.Dir(path)
	return dir == "/etc/sudoers.d" || strings.HasSuffix(dir, "/etc/sudoers.d")
}

func isUnitConfiguration(path string) bool {
	if !strings.HasSuffix(path, ".service") && !(strings.HasSuffix(path, ".conf") && strings.HasSuffix(filepath.Dir(path), ".service.d")) {
		return false
	}
	for _, dir := range unitDirectories {
		if strings.HasPrefix(path, dir) || strings.Contains(path, dir) {
			return true
		}
	}
	return false
}
