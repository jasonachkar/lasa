package network

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jasonachkar/lasa/internal/domain"
)

func Endpoint(s string, v6 bool) (string, uint16, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("socket: missing port separator")
	}
	size := 8
	if v6 {
		size = 32
	}
	if len(a) != size || len(p) != 4 {
		return "", 0, fmt.Errorf("socket: invalid endpoint length")
	}
	b, e := hex.DecodeString(a)
	if e != nil {
		return "", 0, e
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+3] = b[i+3], b[i]
		b[i+1], b[i+2] = b[i+2], b[i+1]
	}
	n, e := strconv.ParseUint(p, 16, 16)
	if e != nil {
		return "", 0, e
	}
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return "", 0, fmt.Errorf("socket: invalid address")
	}
	return ip.String(), uint16(n), nil
}
func ParseTable(b []byte, proto string, v6 bool, ns string) ([]domain.Socket, error) {
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("socket table exceeds budget")
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "local_address") {
		return nil, fmt.Errorf("socket table: invalid header")
	}
	var out []domain.Socket
	for i, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			return nil, fmt.Errorf("socket table row %d: expected 10 fields", i+2)
		}
		a, port, e := Endpoint(f[1], v6)
		if e != nil {
			return nil, fmt.Errorf("socket row %d: %w", i+2, e)
		}
		inode, e := strconv.ParseUint(f[9], 10, 64)
		if e != nil {
			return nil, fmt.Errorf("socket row %d inode: %w", i+2, e)
		}
		state, e := strconv.ParseUint(f[3], 16, 8)
		if e != nil {
			return nil, fmt.Errorf("socket row %d state: %w", i+2, e)
		}
		if proto == "tcp" && state != 10 {
			continue
		}
		if proto == "udp" && port == 0 {
			continue
		}
		family := "ipv4"
		if v6 {
			family = "ipv6"
		}
		ex := domain.Potential
		addr, _ := netip.ParseAddr(a)
		if addr.Unmap().IsLoopback() {
			ex = domain.Local
		}
		out = append(out, domain.Socket{ID: domain.Hash(ns, proto, f[9], f[1]), Protocol: proto, Family: family, Address: a, Port: port, State: map[bool]string{true: "listening", false: "bound"}[proto == "tcp"], Inode: inode, Namespace: ns, Exposure: ex})
		if len(out) > 32768 {
			return nil, fmt.Errorf("socket count exceeds budget")
		}
	}
	return out, nil
}
func ParseUnix(b []byte, ns string) ([]domain.Socket, error) {
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("unix table exceeds budget")
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "Inode") {
		return nil, fmt.Errorf("unix table: invalid header")
	}
	var out []domain.Socket
	for i, s := range lines[1:] {
		f := strings.Fields(s)
		if len(f) < 7 {
			return nil, fmt.Errorf("unix row %d: truncated", i+2)
		}
		inode, e := strconv.ParseUint(f[6], 10, 64)
		if e != nil {
			return nil, e
		}
		path := ""
		if len(f) > 7 {
			path = strings.Join(f[7:], " ")
		}
		out = append(out, domain.Socket{ID: domain.Hash(ns, "unix", f[6]), Protocol: "unix", Family: "unix", Address: path, State: f[5], Inode: inode, Namespace: ns, Exposure: domain.Local})
	}
	return out, nil
}
