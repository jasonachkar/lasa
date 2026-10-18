package identity

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jasonachkar/lasa/internal/domain"
)

func InitialMapping(s string) bool {
	f := strings.Fields(s)
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}
func Unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", fmt.Errorf("mountinfo: truncated escape")
		}
		switch s[i+1 : i+4] {
		case "040":
			b.WriteByte(' ')
		case "011":
			b.WriteByte('\t')
		case "012":
			b.WriteByte('\n')
		case "134":
			b.WriteByte('\\')
		default:
			return "", fmt.Errorf("mountinfo: invalid escape")
		}
		i += 3
	}
	return b.String(), nil
}
func ParseMounts(b []byte, ns string) ([]domain.Mount, error) {
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("mountinfo exceeds budget")
	}
	var out []domain.Mount
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			return nil, fmt.Errorf("mountinfo: missing separator")
		}
		f, g := strings.Fields(left), strings.Fields(right)
		if len(f) < 6 || len(g) < 3 {
			return nil, fmt.Errorf("mountinfo: truncated fields")
		}
		id, e := strconv.Atoi(f[0])
		if e != nil {
			return nil, fmt.Errorf("mountinfo id: %w", e)
		}
		parent, e := strconv.Atoi(f[1])
		if e != nil {
			return nil, e
		}
		target, e := Unescape(f[4])
		if e != nil {
			return nil, e
		}
		root, e := Unescape(f[3])
		if e != nil {
			return nil, e
		}
		source, e := Unescape(g[1])
		if e != nil {
			return nil, e
		}
		out = append(out, domain.Mount{ID: domain.Hash(ns, f[0]), Parent: parent, Device: f[2], Root: root, Target: target, Options: strings.Split(f[5], ","), Optional: f[6:], Filesystem: g[0], Source: source, Namespace: ns})
		if id < 0 || len(out) > 16384 {
			return nil, fmt.Errorf("mountinfo: invalid id or mount budget exceeded")
		}
	}
	return out, nil
}
