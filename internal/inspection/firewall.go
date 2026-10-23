package inspection

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"

	"github.com/jasonachkar/lasa/internal/domain"
)

type Packet struct {
	Source, Destination netip.Addr
	Protocol, Interface string
	Port                uint16
}
type nftChain struct {
	Family, Table, Name, Hook, Policy string
	Priority                          int
	Rules                             [][]json.RawMessage
}
type Firewall struct {
	Chains      map[string]*nftChain
	Unsupported bool
}

func ParseFirewall(raw []byte) (Firewall, error) {
	f := Firewall{Chains: map[string]*nftChain{}}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if e := json.Unmarshal(raw, &doc); e != nil {
		return f, fmt.Errorf("invalid nftables JSON")
	}
	if doc.NFTables == nil {
		return f, fmt.Errorf("missing nftables array")
	}
	var rules []struct {
		Family, Table, Chain string
		Expr                 []json.RawMessage
	}
	for _, obj := range doc.NFTables {
		if v, ok := obj["chain"]; ok {
			var c struct {
				Family, Table, Name, Hook, Policy, Type string
				Prio                                    json.RawMessage `json:"prio"`
			}
			if json.Unmarshal(v, &c) != nil {
				return f, fmt.Errorf("invalid nftables chain")
			}
			ch := &nftChain{Family: c.Family, Table: c.Table, Name: c.Name, Hook: c.Hook, Policy: c.Policy}
			if len(c.Prio) > 0 && json.Unmarshal(c.Prio, &ch.Priority) != nil {
				f.Unsupported = true
			}
			if c.Hook != "" && (c.Policy != "accept" && c.Policy != "drop" || c.Type != "filter") {
				f.Unsupported = true
			}
			if c.Hook != "" && c.Hook != "input" {
				f.Unsupported = true
			}
			if c.Type != "" && c.Type != "filter" {
				f.Unsupported = true
			}
			key := c.Family + "/" + c.Table + "/" + c.Name
			if _, exists := f.Chains[key]; exists {
				return f, fmt.Errorf("duplicate nftables chain")
			}
			f.Chains[key] = ch
		}
		if v, ok := obj["rule"]; ok {
			var r struct {
				Family, Table, Chain string
				Expr                 []json.RawMessage
			}
			if json.Unmarshal(v, &r) != nil {
				return f, fmt.Errorf("invalid nftables rule")
			}
			rules = append(rules, r)
		}
		for key := range obj {
			if !slices.Contains([]string{"metainfo", "table", "chain", "rule", "set", "counter"}, key) {
				f.Unsupported = true
			}
			if key == "set" {
				f.Unsupported = true
			}
		}
	}
	for _, r := range rules {
		ch := f.Chains[r.Family+"/"+r.Table+"/"+r.Chain]
		if ch == nil {
			return f, fmt.Errorf("nftables rule references unknown chain")
		}
		ch.Rules = append(ch.Rules, r.Expr)
	}
	return f, nil
}

// Verdict covers only the supported local nftables model. It never establishes
// upstream reachability, legacy iptables behavior, XDP/tc filtering or NAT.
func (f Firewall) Verdict(p Packet) string {
	if f.Unsupported {
		return "unknown"
	}
	var bases []*nftChain
	for _, c := range f.Chains {
		if c.Hook == "input" && (c.Family == "inet" || c.Family == "ip" && p.Destination.Is4() || c.Family == "ip6" && p.Destination.Is6()) {
			bases = append(bases, c)
		}
	}
	sort.Slice(bases, func(i, j int) bool {
		if bases[i].Priority != bases[j].Priority {
			return bases[i].Priority < bases[j].Priority
		}
		return bases[i].Name < bases[j].Name
	})
	if len(bases) == 0 {
		return "accepted"
	}
	result := "accepted"
	for _, c := range bases {
		v := f.chain(c, p, 0, map[string]bool{})
		if v == "drop" || v == "reject" {
			return "blocked"
		}
		if v != "accept" {
			result = "unknown"
		}
	}
	return result
}
func (f Firewall) chain(c *nftChain, p Packet, depth int, visiting map[string]bool) string {
	key := c.Family + "/" + c.Table + "/" + c.Name
	if depth > 16 || visiting[key] {
		return "unknown"
	}
	visiting[key] = true
	defer delete(visiting, key)
	for _, expr := range c.Rules {
		match := true
		action := ""
		for _, raw := range expr {
			var op map[string]json.RawMessage
			if json.Unmarshal(raw, &op) != nil || len(op) != 1 {
				return "unknown"
			}
			for kind, v := range op {
				switch kind {
				case "match":
					ok, known := nftMatch(v, p)
					if !known {
						return "unknown"
					}
					match = match && ok
				case "counter", "comment", "log":
				case "accept", "drop", "reject", "return":
					action = kind
				case "jump", "goto":
					var to struct {
						Target string `json:"target"`
					}
					if json.Unmarshal(v, &to) != nil {
						return "unknown"
					}
					child := f.Chains[c.Family+"/"+c.Table+"/"+to.Target]
					if child == nil {
						return "unknown"
					}
					if match {
						action = f.chain(child, p, depth+1, visiting)
						if action == "return" {
							if kind == "goto" {
								if c.Hook != "" {
									return c.Policy
								}
								return "return"
							}
							action = ""
						}
					}
				default:
					return "unknown"
				}
			}
		}
		if match && action != "" {
			if action == "return" && c.Hook != "" {
				return c.Policy
			}
			return action
		}
	}
	if c.Hook == "" {
		return "return"
	}
	switch c.Policy {
	case "accept":
		return "accept"
	case "drop":
		return "drop"
	default:
		return "unknown"
	}
}
func nftMatch(raw []byte, p Packet) (bool, bool) {
	var m struct {
		Op    string                     `json:"op"`
		Left  map[string]json.RawMessage `json:"left"`
		Right json.RawMessage            `json:"right"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return false, false
	}
	if m.Op != "==" && m.Op != "!=" && m.Op != "in" {
		return false, false
	}
	if len(m.Left) != 1 {
		return false, false
	}
	var actual any
	for kind, v := range m.Left {
		switch kind {
		case "payload":
			var field struct{ Protocol, Field string }
			if json.Unmarshal(v, &field) != nil {
				return false, false
			}
			switch field.Field {
			case "dport":
				if field.Protocol != "tcp" && field.Protocol != "udp" {
					return false, false
				}
				if p.Protocol != field.Protocol {
					return false, true
				}
				actual = int(p.Port)
			case "saddr":
				if field.Protocol != "ip" && field.Protocol != "ip6" {
					return false, false
				}
				if field.Protocol == "ip" && !p.Destination.Is4() || field.Protocol == "ip6" && !p.Destination.Is6() {
					return false, true
				}
				if !p.Source.IsValid() {
					return false, false
				}
				actual = p.Source
			case "daddr":
				if field.Protocol != "ip" && field.Protocol != "ip6" {
					return false, false
				}
				if field.Protocol == "ip" && !p.Destination.Is4() || field.Protocol == "ip6" && !p.Destination.Is6() {
					return false, true
				}
				actual = p.Destination
			default:
				return false, false
			}
		case "meta":
			var field struct{ Key string }
			if json.Unmarshal(v, &field) != nil {
				return false, false
			}
			switch field.Key {
			case "l4proto":
				actual = p.Protocol
			case "iifname":
				if p.Interface == "" {
					return false, false
				}
				actual = p.Interface
			case "nfproto":
				if p.Destination.Is4() {
					actual = "ipv4"
				} else {
					actual = "ipv6"
				}
			default:
				return false, false
			}
		case "ct":
			var field struct{ Key string }
			if json.Unmarshal(v, &field) != nil || field.Key != "state" {
				return false, false
			}
			actual = "new"
		default:
			return false, false
		}
	}
	match, known := nftValue(actual, m.Right)
	if known && m.Op == "!=" {
		match = !match
	}
	return match, known
}
func nftValue(actual any, raw json.RawMessage) (bool, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch a := actual.(type) {
		case string:
			return a == s, true
		case netip.Addr:
			addr, e := netip.ParseAddr(s)
			return a == addr, e == nil
		}
		return false, false
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		a, ok := actual.(int)
		return a == n, ok
	}
	var compound map[string]json.RawMessage
	if json.Unmarshal(raw, &compound) != nil {
		return false, false
	}
	if set, ok := compound["set"]; ok {
		var values []json.RawMessage
		if json.Unmarshal(set, &values) != nil || len(values) > 4096 {
			return false, false
		}
		known := true
		for _, value := range values {
			yes, k := nftValue(actual, value)
			if yes && k {
				return true, true
			}
			known = known && k
		}
		return false, known
	}
	if value, ok := compound["prefix"]; ok {
		var prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if json.Unmarshal(value, &prefix) != nil {
			return false, false
		}
		a, ok := actual.(netip.Addr)
		network, e := netip.ParsePrefix(prefix.Addr + "/" + strconv.Itoa(prefix.Len))
		return ok && network.Contains(a), e == nil && ok
	}
	if value, ok := compound["range"]; ok {
		var bounds []int
		if json.Unmarshal(value, &bounds) != nil || len(bounds) != 2 || bounds[0] > bounds[1] {
			return false, false
		}
		a, ok := actual.(int)
		return ok && a >= bounds[0] && a <= bounds[1], ok
	}
	return false, false
}
func (i *inspection) firewall() {
	if name := i.c.Config.NetworkInterface; name != "" {
		found := false
		for _, iface := range i.c.Snapshot.Interfaces {
			found = found || iface.Name == name
		}
		if !found {
			i.fail("validate_ingress_interface", "--network-interface", fmt.Errorf("interface is not present in the observed scanner namespace"))
			return
		}
	}
	raw, e := i.runner.Run(i.ctx, "nft", "-j", "list", "ruleset")
	if e != nil {
		i.fail("read_nftables", "scanner network namespace", e)
		return
	}
	f, e := ParseFirewall(raw)
	if e != nil {
		i.fail("parse_nftables", "scanner network namespace", e)
		return
	}
	var source, destination netip.Addr
	if i.c.Config.NetworkSource != "" {
		source, e = netip.ParseAddr(i.c.Config.NetworkSource)
		if e != nil {
			i.fail("parse_source", "--network-source", e)
			return
		}
	}
	if i.c.Config.NetworkDestination != "" {
		destination, e = netip.ParseAddr(i.c.Config.NetworkDestination)
		if e != nil {
			i.fail("parse_destination", "--network-destination", e)
			return
		}
		local := false
		for _, iface := range i.c.Snapshot.Interfaces {
			for _, address := range iface.Addresses {
				prefix, err := netip.ParsePrefix(address)
				if err == nil && prefix.Addr() == destination {
					local = true
				}
			}
		}
		if !local {
			i.fail("validate_destination", "--network-destination", fmt.Errorf("destination is not an observed scanner-namespace interface address"))
			return
		}
	}
	for _, socket := range i.c.Snapshot.Sockets {
		if socket.Protocol != "tcp" && socket.Protocol != "udp" {
			continue
		}
		if !i.next(socket.ID) {
			break
		}
		a := i.asset("nftables_endpoint", socket.Protocol+" "+socket.Address+":"+strconv.Itoa(int(socket.Port)))
		if socket.Namespace != i.c.Snapshot.Host.NetworkNamespace {
			i.unsupported(a.Label, "nftables was inspected only in the scanner network namespace")
			continue
		}
		addr, err := netip.ParseAddr(socket.Address)
		if err != nil {
			i.fail("parse_endpoint", socket.ID, err)
			continue
		}
		if addr.IsUnspecified() {
			if destination.IsValid() && addr.Is4() != destination.Is4() {
				i.unsupported(a.Label, "destination address family does not match the wildcard listener")
				continue
			}
			addr = destination
		}
		if !addr.IsValid() {
			i.unsupported(a.Label, "wildcard listener requires an observed --network-destination address")
			continue
		}
		if source.IsValid() && source.Is4() != addr.Is4() {
			continue
		}
		verdict := f.Verdict(Packet{Source: source, Destination: addr, Protocol: socket.Protocol, Port: socket.Port, Interface: i.c.Config.NetworkInterface})
		refs := []string{i.fact(a, "firewall.nft_verdict", verdict, "nft -j list ruleset", domain.Observed), i.fact(a, "firewall.packet", fmt.Sprintf("source=%s destination=%s protocol=%s port=%d interface=%s state=new", source, addr, socket.Protocol, socket.Port, i.c.Config.NetworkInterface), a.Label, domain.Observed), i.fact(a, "asset.related_subject", socket.ID, a.Label, domain.Observed)}
		state := domain.Observed
		if verdict == "unknown" {
			i.unsupported(a.Label, "ruleset contains unsupported/ambiguous conditions or missing packet context")
			state = domain.Unknown
		}
		management := slices.Contains([]uint16{22, 2375, 2376, 3389, 5432, 6379, 6443, 9200, 10250, 27017}, socket.Port)
		i.risk(a, "firewall.management_permitted", management && verdict == "accepted" && !addr.IsLoopback(), state, refs...)
		i.b.Coverage.Successful++
	}
}
