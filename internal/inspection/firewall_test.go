package inspection

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func firewallFixture(policy string, expr string) []byte {
	return []byte(`{"nftables":[{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"` + policy + `"}},{"rule":{"family":"inet","table":"filter","chain":"input","expr":` + expr + `}}]}`)
}
func TestFirewallPacketMatchingAndUnsupportedControls(t *testing.T) {
	p := Packet{Source: netip.MustParseAddr("192.0.2.5"), Destination: netip.MustParseAddr("198.51.100.10"), Protocol: "tcp", Port: 22, Interface: "eth0"}
	expr := `[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},{"accept":null}]`
	f, e := ParseFirewall(firewallFixture("drop", expr))
	if e != nil || f.Verdict(p) != "accepted" {
		t.Fatalf("%+v %v", f, e)
	}
	p.Source = netip.MustParseAddr("203.0.113.1")
	if f.Verdict(p) != "blocked" {
		t.Fatal("source constraint ignored")
	}
	p.Source = netip.Addr{}
	if f.Verdict(p) != "unknown" {
		t.Fatal("missing packet context treated as known")
	}
	f, e = ParseFirewall(firewallFixture("drop", `[{"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":1}},{"accept":null}]`))
	if e != nil || f.Verdict(p) != "unknown" {
		t.Fatal("unsupported mark accepted")
	}
	f, e = ParseFirewall([]byte(`{"nftables":[]}`))
	if e != nil || f.Verdict(p) != "accepted" {
		t.Fatal("empty nftables policy should not imply filtering")
	}
	if _, e = ParseFirewall([]byte(`{}`)); e == nil {
		t.Fatal("missing nftables document accepted")
	}
}
func TestFirewallAllBaseChainsAndReturns(t *testing.T) {
	raw := []byte(`{"nftables":[{"chain":{"family":"inet","table":"f","name":"one","type":"filter","hook":"input","prio":0,"policy":"accept"}},{"chain":{"family":"inet","table":"f","name":"two","type":"filter","hook":"input","prio":10,"policy":"drop"}},{"rule":{"family":"inet","table":"f","chain":"one","expr":[{"accept":null}]}}]}`)
	f, e := ParseFirewall(raw)
	p := Packet{Destination: netip.MustParseAddr("198.51.100.10"), Protocol: "tcp", Port: 22}
	if e != nil || f.Verdict(p) != "blocked" {
		t.Fatal("early accept bypassed later base chain", e)
	}
	f, e = ParseFirewall(firewallFixture("drop", `[{"return":null}]`))
	if e != nil || f.Verdict(p) != "blocked" {
		t.Fatal("base return did not apply policy")
	}
}
func TestFirewallJumpAndSetMatching(t *testing.T) {
	var doc map[string][]any
	_ = json.Unmarshal(firewallFixture("drop", `[{"jump":{"target":"ssh"}}]`), &doc)
	doc["nftables"] = append(doc["nftables"], map[string]any{"chain": map[string]any{"family": "inet", "table": "filter", "name": "ssh"}}, map[string]any{"rule": map[string]any{"family": "inet", "table": "filter", "chain": "ssh", "expr": []any{map[string]any{"match": map[string]any{"op": "in", "left": map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}, "right": map[string]any{"set": []int{22, 443}}}}, map[string]any{"accept": nil}}}})
	raw, _ := json.Marshal(doc)
	f, e := ParseFirewall(raw)
	if e != nil {
		t.Fatal(e)
	}
	p := Packet{Destination: netip.MustParseAddr("192.0.2.1"), Protocol: "tcp", Port: 22}
	if f.Verdict(p) != "accepted" {
		t.Fatal("jump/set not evaluated")
	}
	p.Port = 25
	if f.Verdict(p) != "blocked" {
		t.Fatal("unmatched user chain should return to drop base policy")
	}
}
func FuzzFirewall(f *testing.F) {
	f.Add(string(firewallFixture("drop", `[{"accept":null}]`)))
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		if parsed, e := ParseFirewall([]byte(s)); e == nil {
			_ = parsed.Verdict(Packet{Destination: netip.MustParseAddr("192.0.2.1"), Protocol: "tcp", Port: 22})
		}
	})
}
