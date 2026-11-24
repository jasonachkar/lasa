package rules

import "sort"

// Predicate documents a registered predicate for rule authors.
type Predicate struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
	Description string `json:"description"`
}

var predicateDocs = map[string][2]string{
	"network.potential":         {"process", "Owns a TCP/UDP endpoint bound to a non-loopback or wildcard address. Unknown when descriptors or network tables were not fully visible."},
	"network.management":        {"process", "A potentially exposed endpoint uses a conventional management or database port (22, 2375, 2376, 3389, 5432, 6379, 6443, 9200, 10250, 27017)."},
	"network.confirmed":         {"process", "Independently confirmed external exposure. Static scans never observe this; it is always unknown."},
	"privilege.host_root":       {"process", "Effective UID 0 in the initial user namespace with an identity mapping."},
	"capability.dangerous":      {"process", "Holds a dangerous effective capability (for example CAP_SYS_ADMIN) in the initial user namespace."},
	"isolation.weak":            {"process", "Seccomp is disabled and NoNewPrivs is off."},
	"container.hint":            {"process", "Cgroup naming suggests a container runtime. A heuristic, not proof of a boundary."},
	"container.host_pid":        {"process", "Belongs to the initial PID namespace."},
	"container.sensitive_mount": {"process", "Its mount namespace has a host-style /host/etc, /host/proc or /host/sys mount."},
	"identity.euid":             {"process", "Effective UID (unsigned 32-bit number)."},
	"file.kind":                 {"file", "Location-based kind: sudoers, authorized_keys, service_config, runtime_socket, directory, executable or other."},
	"file.write_candidate":      {"file", "Writable by other users, or by a non-root group, and not on a read-only mount. ACLs and LSM policy are not evaluated."},
	"file.unsafe_parent":        {"file", "A scoped ancestor directory is a write candidate. Observed only when true; otherwise unknown."},
	"file.privileged_execution": {"file", "The inode is the executable of an observed initial-namespace root process. Observed only when true."},
	"file.executable":           {"file", "A regular file with an execute bit."},
	"file.suid":                 {"file", "The set-user-ID bit is set."},
	"file.sgid":                 {"file", "The set-group-ID bit is set."},
	"file.owner_root":           {"file", "Owned by UID 0."},
	"file.capability":           {"file", "Carries enabled file capabilities (security.capability xattr)."},
	"file.acl_present":          {"file", "Has a POSIX access ACL."},
	"file.readonly":             {"file", "Resides on a read-only mount."},
	"file.search_path":          {"file", "Is a conventional command search directory root (/usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin)."},
}

// Predicates lists every registered predicate with its type and meaning.
func Predicates() []Predicate {
	out := make([]Predicate, 0, len(registry))
	for name, typ := range registry {
		doc := predicateDocs[name]
		out = append(out, Predicate{Name: name, Type: typ, Subject: doc[0], Description: doc[1]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject > out[j].Subject
		}
		return out[i].Name < out[j].Name
	})
	return out
}
