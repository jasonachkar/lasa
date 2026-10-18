package process

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/jasonachkar/lasa/internal/domain"
)

func ParseStat(b []byte) (int, int, uint64, error) {
	if len(b) > 1<<20 {
		return 0, 0, 0, fmt.Errorf("stat exceeds budget")
	}
	s := string(b)
	i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if i < 1 || j <= i {
		return 0, 0, 0, fmt.Errorf("stat: missing parenthesized command")
	}
	pid, e := strconv.Atoi(strings.TrimSpace(s[:i]))
	if e != nil || pid <= 0 {
		return 0, 0, 0, fmt.Errorf("stat: invalid PID")
	}
	f := strings.Fields(s[j+1:])
	if len(f) < 20 {
		return 0, 0, 0, fmt.Errorf("stat: truncated fields (%d; need 20 after command)", len(f))
	}
	ppid, e := strconv.Atoi(f[1])
	if e != nil || ppid < 0 {
		return 0, 0, 0, fmt.Errorf("stat: invalid PPID")
	}
	start, e := strconv.ParseUint(f[19], 10, 64)
	if e != nil {
		return 0, 0, 0, fmt.Errorf("stat: invalid starttime: %w", e)
	}
	return pid, ppid, start, nil
}
func ParseStatus(b []byte) (domain.Process, error) {
	if len(b) > 1<<20 {
		return domain.Process{}, fmt.Errorf("status exceeds 1MiB")
	}
	p := domain.Process{Seccomp: -1, SeccompFilters: -1, NoNewPrivs: -1, Capabilities: map[string]uint64{}, Namespaces: map[string]string{}}
	seen := map[string]bool{}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 1024), 1<<20)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		if seen[k] {
			return p, fmt.Errorf("status: duplicate field %s", k)
		}
		seen[k] = true
		f := strings.Fields(v)
		switch k {
		case "Name":
			p.Name = strings.TrimSpace(v)
		case "Uid", "Gid":
			if len(f) != 4 {
				return p, fmt.Errorf("status: %s requires 4 credentials", k)
			}
			var ids [4]uint32
			for i, x := range f {
				n, e := strconv.ParseUint(x, 10, 32)
				if e != nil {
					return p, fmt.Errorf("status %s: %w", k, e)
				}
				ids[i] = uint32(n)
			}
			if k == "Uid" {
				p.Identity.UID = ids
			} else {
				p.Identity.GID = ids
			}
		case "Groups":
			for _, x := range f {
				n, e := strconv.ParseUint(x, 10, 32)
				if e != nil {
					return p, fmt.Errorf("status groups: %w", e)
				}
				p.Identity.Groups = append(p.Identity.Groups, uint32(n))
			}
		case "CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb":
			if len(f) != 1 {
				return p, fmt.Errorf("status: malformed %s", k)
			}
			n, e := strconv.ParseUint(f[0], 16, 64)
			if e != nil {
				return p, fmt.Errorf("status %s: %w", k, e)
			}
			p.Capabilities[k] = n
		case "Seccomp", "Seccomp_filters", "NoNewPrivs":
			if len(f) != 1 {
				return p, fmt.Errorf("status: malformed %s", k)
			}
			n, e := strconv.Atoi(f[0])
			if e != nil || n < 0 {
				return p, fmt.Errorf("status: invalid %s", k)
			}
			switch k {
			case "Seccomp":
				if n > 2 {
					return p, fmt.Errorf("status: unsupported seccomp mode %d", n)
				}
				p.Seccomp = n
			case "Seccomp_filters":
				p.SeccompFilters = n
			case "NoNewPrivs":
				if n > 1 {
					return p, fmt.Errorf("status: invalid NoNewPrivs")
				}
				p.NoNewPrivs = n
			}
		}
	}
	if e := s.Err(); e != nil {
		return p, e
	}
	if !seen["Uid"] || !seen["Gid"] {
		return p, fmt.Errorf("status: missing required Uid/Gid")
	}
	return p, nil
}
