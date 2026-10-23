package application

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jasonachkar/lasa/internal/domain"
)

// SurfaceChange describes observed changes, never verified exploitability or a
// guarantee that an absent listener is unreachable outside the declared scope.
type SurfaceChange struct {
	Kind    string       `json:"kind"`
	Subject string       `json:"subject"`
	State   domain.State `json:"state"`
	Before  []string     `json:"before,omitempty"`
	After   []string     `json:"after,omitempty"`
}

func surfaceChanges(old, now domain.Snapshot) ([]SurfaceChange, bool) {
	type entry struct {
		kind, label string
		values      []string
	}
	index := func(s domain.Snapshot) map[string]entry {
		out := map[string]entry{}
		add := func(kind, key, label, value string) {
			id := kind + ":" + key
			e := out[id]
			e.kind = kind
			e.label = label
			e.values = append(e.values, value)
			out[id] = e
		}
		for _, socket := range s.Sockets {
			if socket.Protocol != "tcp" && socket.Protocol != "udp" {
				continue
			}
			scope := socket.Namespace
			if scope == s.Host.NetworkNamespace {
				scope = "scanner-network-namespace"
			}
			label := fmt.Sprintf("%s %s:%d (%s)", socket.Protocol, socket.Address, socket.Port, scope)
			add("listener", label, label, "observed "+socket.State)
		}
		for _, p := range s.Processes {
			value := fmt.Sprintf("euid=%d egid=%d effective_capabilities=%#x seccomp=%d no_new_privs=%d", p.Identity.UID[1], p.Identity.GID[1], p.Capabilities["CapEff"], p.Seccomp, p.NoNewPrivs)
			add("process_privilege", p.StableID, p.Executable, value)
		}
		for _, f := range s.Files {
			add("file_permissions", f.Path, f.Path, fmt.Sprintf("uid=%d gid=%d mode=%#o capabilities=%s acl=%s read_only=%s", f.UID, f.GID, f.Mode, f.Capabilities, f.ACL, f.ReadOnly))
		}
		labels := map[string]domain.Asset{}
		for _, a := range s.Assets {
			labels[a.ID] = a
		}
		for _, o := range s.Observations {
			a, ok := labels[o.Subject]
			if !ok || o.State != domain.Observed {
				continue
			}
			if o.Key == "systemd.execution_path" || o.Key == "systemd.User" || o.Key == "systemd.Group" || o.Key == "ssh.permitrootlogin" || o.Key == "ssh.passwordauthentication" || o.Key == "ssh.authenticationmethods" || o.Key == "ssh.strictmodes" || o.Key == "sudo.root_command" || o.Key == "sudo.unrestricted_root" || o.Key == "sudo.passwordless_root" || o.Key == "container.runtime_state" || o.Key == "container.mount" || o.Key == "container.added_capability" || o.Key == "packages.installed" {
				add("inspection_policy", a.StableID+":"+o.Key, a.Label+" / "+o.Key, o.Value)
			}
		}
		for key, e := range out {
			slices.Sort(e.values)
			e.values = slices.Compact(e.values)
			out[key] = e
		}
		return out
	}
	before, after := index(old), index(now)
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	var changes []SurfaceChange
	for _, key := range ordered {
		a, aOK := before[key]
		b, bOK := after[key]
		if aOK && bOK && slices.Equal(a.values, b.values) {
			continue
		}
		state := domain.Observed
		kind, label := b.kind, b.label
		if !bOK {
			kind, label = a.kind, a.label
			state = domain.NotObserved
			if !now.Complete || old.ScopeFingerprint == "" || now.ScopeFingerprint == "" || old.ScopeFingerprint != now.ScopeFingerprint || old.Profile != now.Profile {
				state = domain.Unknown
			}
		}
		if kind == "process_privilege" && old.Host.BootID != now.Host.BootID {
			state = domain.Unknown
		}
		changes = append(changes, SurfaceChange{Kind: kind, Subject: label, State: state, Before: a.values, After: b.values})
		if len(changes) >= 10000 {
			return changes, true
		}
	}
	return changes, false
}
func canonicalEvidence(ids []string) string {
	copyIDs := append([]string(nil), ids...)
	slices.Sort(copyIDs)
	copyIDs = slices.Compact(copyIDs)
	raw, _ := json.Marshal(copyIDs)
	return strings.TrimSpace(string(raw))
}
