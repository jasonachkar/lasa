// Package domain defines the versioned, platform-independent evidence contract.
package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

const SchemaVersion = "lasa.report/v2"
const LegacySchemaVersion = "lasa.report/v1"

// Version is injected by release builds. The default identifies source builds.
var Version = "0.1.0-dev"

type State string

const (
	Observed      State = "observed"
	NotObserved   State = "not_observed"
	Unknown       State = "unknown"
	NotApplicable State = "not_applicable"
)

type Exposure string

const (
	Confirmed       Exposure = "confirmed"
	Potential       Exposure = "potential"
	Local           Exposure = "local"
	UnknownExposure Exposure = "unknown"
)

type Diagnostic struct {
	Code        string `json:"code"`
	Component   string `json:"component"`
	Operation   string `json:"operation"`
	Target      string `json:"target"`
	Cause       string `json:"cause"`
	Errno       int    `json:"errno,omitempty"`
	Requirement string `json:"requirement,omitempty"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
	Recoverable bool   `json:"recoverable"`
}

func (d Diagnostic) Error() string {
	return fmt.Sprintf("%s: %s %s (%s): %s; impact: %s; action: %s", d.Code, d.Operation, d.Target, d.Component, d.Cause, d.Impact, d.Remediation)
}

type Observation struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	State     State     `json:"state"`
	Source    string    `json:"source"`
	Collector string    `json:"collector"`
	At        time.Time `json:"at"`
	Derived   bool      `json:"derived"`
	Redacted  bool      `json:"redacted"`
	ErrorCode string    `json:"error_code,omitempty"`
	Evidence  []string  `json:"evidence,omitempty"`
}
type Coverage struct {
	Collector    string    `json:"collector"`
	Version      string    `json:"version"`
	Started      time.Time `json:"started"`
	Completed    time.Time `json:"completed"`
	Attempted    int       `json:"attempted"`
	Successful   int       `json:"successful"`
	Skipped      int       `json:"skipped"`
	Unsupported  int       `json:"unsupported"`
	Inconclusive int       `json:"inconclusive"`
	Complete     bool      `json:"complete"`
	Scope        string    `json:"scope"`
}
type Host struct {
	ID               string `json:"id"`
	BootID           string `json:"boot_id"`
	OS               string `json:"os"`
	Distribution     string `json:"distribution"`
	Kernel           string `json:"kernel"`
	Architecture     string `json:"architecture"`
	Scope            string `json:"scope"`
	PIDNamespace     string `json:"pid_namespace"`
	UserNamespace    string `json:"user_namespace"`
	NetworkNamespace string `json:"network_namespace"`
}
type Credentials struct {
	UID    [4]uint32 `json:"uid"`
	GID    [4]uint32 `json:"gid"`
	Groups []uint32  `json:"groups"`
	UIDMap string    `json:"uid_map"`
	GIDMap string    `json:"gid_map"`
}
type Process struct {
	ID               string            `json:"id"`
	StableID         string            `json:"stable_id"`
	PID              int               `json:"pid"`
	PPID             int               `json:"ppid"`
	StartTime        uint64            `json:"start_time_ticks"`
	Name             string            `json:"name"`
	Executable       string            `json:"executable"`
	ExecutableInode  uint64            `json:"executable_inode"`
	ExecutableDevice uint64            `json:"executable_device"`
	Identity         Credentials       `json:"identity"`
	Capabilities     map[string]uint64 `json:"capabilities"`
	Namespaces       map[string]string `json:"namespaces"`
	Seccomp          int               `json:"seccomp"`
	SeccompFilters   int               `json:"seccomp_filters"`
	NoNewPrivs       int               `json:"no_new_privs"`
	Cgroups          []string          `json:"cgroups"`
	SocketInodes     []uint64          `json:"socket_inodes"`
	FDComplete       bool              `json:"fd_complete"`
	ContainerHint    bool              `json:"container_hint"`
	Service          string            `json:"service,omitempty"`
}
type Socket struct {
	ID        string   `json:"id"`
	Protocol  string   `json:"protocol"`
	Family    string   `json:"family"`
	Address   string   `json:"address"`
	Port      uint16   `json:"port"`
	State     string   `json:"state"`
	Inode     uint64   `json:"inode"`
	Namespace string   `json:"namespace"`
	Owners    []string `json:"owners"`
	Exposure  Exposure `json:"exposure"`
}
type Interface struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	Addresses []string `json:"addresses"`
	Flags     string   `json:"flags"`
	Namespace string   `json:"namespace"`
}
type Mount struct {
	ID         string   `json:"id"`
	Parent     int      `json:"parent"`
	Device     string   `json:"device"`
	Root       string   `json:"root"`
	Target     string   `json:"target"`
	Options    []string `json:"options"`
	Optional   []string `json:"optional"`
	Filesystem string   `json:"filesystem"`
	Source     string   `json:"source"`
	Namespace  string   `json:"namespace"`
}
type File struct {
	ID           string `json:"id"`
	Path         string `json:"path"`
	Inode        uint64 `json:"inode"`
	Device       uint64 `json:"device"`
	Mode         uint32 `json:"mode"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	Capabilities string `json:"capabilities,omitempty"`
	ACL          State  `json:"acl"`
	ReadOnly     State  `json:"read_only"`
	Kind         string `json:"kind"`
}
type Service struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Process       string `json:"process"`
	Configuration string `json:"configuration,omitempty"`
	Source        string `json:"source"`
}
type Container struct {
	ID         string `json:"id"`
	Process    string `json:"process"`
	Hint       string `json:"hint"`
	Confidence string `json:"confidence"`
}

// Asset is an explicitly inspected configuration, identity, endpoint or package.
// Details are retained as allowlisted observations, never raw configuration.
type Asset struct {
	ID       string `json:"id"`
	StableID string `json:"stable_id"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
}

type KernelControl struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	State  State  `json:"state"`
	Source string `json:"source"`
}
type Node struct {
	ID       string `json:"id"`
	StableID string `json:"stable_id"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
}
type Edge struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Type     string   `json:"type"`
	Evidence []string `json:"evidence"`
}
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
type Factor struct {
	Name         string `json:"name"`
	Contribution int    `json:"contribution"`
	Reason       string `json:"reason"`
}
type AttackPath struct {
	ID              string   `json:"id"`
	Entities        []string `json:"entities"`
	Edges           []Edge   `json:"edges"`
	Evidence        []string `json:"evidence"`
	EntryConditions []string `json:"entry_conditions"`
	ConditionalStep string   `json:"conditional_step"`
	PotentialImpact string   `json:"potential_impact"`
	Uncertainties   []string `json:"uncertainties"`
	Factors         []Factor `json:"factors"`
}
type Finding struct {
	ID                string     `json:"id"`
	RuleID            string     `json:"rule_id"`
	RuleVersion       string     `json:"rule_version"`
	Title             string     `json:"title"`
	Description       string     `json:"description"`
	Subject           string     `json:"subject"`
	Subjects          []string   `json:"subjects"`
	StableSubject     string     `json:"stable_subject"`
	Severity          string     `json:"severity"`
	Confidence        string     `json:"confidence"`
	Exposure          Exposure   `json:"exposure"`
	Evidence          []string   `json:"evidence"`
	Prerequisites     []string   `json:"prerequisites"`
	Warnings          []string   `json:"warnings"`
	Remediation       string     `json:"remediation"`
	Priority          int        `json:"priority"`
	ScoreVersion      string     `json:"score_version"`
	Factors           []Factor   `json:"factors"`
	Path              AttackPath `json:"attack_path"`
	Coverage          []string   `json:"coverage"`
	Suppressed        bool       `json:"suppressed"`
	SuppressionReason string     `json:"suppression_reason,omitempty"`
}
type Evaluation struct {
	RuleID   string   `json:"rule_id"`
	Subject  string   `json:"subject"`
	State    State    `json:"state"`
	Evidence []string `json:"evidence"`
	Reason   string   `json:"reason,omitempty"`
}
type RuntimeEvent struct {
	Schema          string `json:"schema"`
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	BootID          string `json:"boot_id"`
	TimestampBootNS uint64 `json:"timestamp_boot_ns"`
	StartBootNS     uint64 `json:"process_start_boot_ns"`
	PID             uint32 `json:"initial_namespace_pid"`
	TID             uint32 `json:"initial_namespace_tid"`
	UID             uint32 `json:"uid"`
	PPID            uint32 `json:"initial_namespace_ppid"`
	Command         string `json:"command_name"`
	Address         string `json:"address,omitempty"`
	Port            uint16 `json:"port,omitempty"`
	Result          int32  `json:"result"`
	Flags           uint64 `json:"namespace_flags,omitempty"`
	StaticSubject   string `json:"static_subject,omitempty"`
}
type Snapshot struct {
	RequestedRoots    []string        `json:"requested_roots,omitempty"`
	Assets            []Asset         `json:"assets,omitempty"`
	Inspections       []string        `json:"inspections,omitempty"`
	ScopeFingerprint  string          `json:"scope_fingerprint,omitempty"`
	Schema            string          `json:"schema"`
	ScannerVersion    string          `json:"scanner_version"`
	ScanID            string          `json:"scan_id"`
	Started           time.Time       `json:"started"`
	Completed         time.Time       `json:"completed"`
	Profile           string          `json:"profile"`
	Host              Host            `json:"host"`
	Processes         []Process       `json:"processes"`
	Sockets           []Socket        `json:"sockets"`
	Interfaces        []Interface     `json:"interfaces"`
	Mounts            []Mount         `json:"mounts"`
	Files             []File          `json:"files"`
	Services          []Service       `json:"services"`
	Containers        []Container     `json:"containers"`
	Controls          []KernelControl `json:"controls"`
	Observations      []Observation   `json:"observations"`
	Graph             Graph           `json:"graph"`
	Findings          []Finding       `json:"findings"`
	Evaluations       []Evaluation    `json:"evaluations"`
	RuntimeEvents     []RuntimeEvent  `json:"runtime_events"`
	LostRuntimeEvents uint64          `json:"lost_runtime_events"`
	Diagnostics       []Diagnostic    `json:"diagnostics"`
	Coverage          []Coverage      `json:"coverage"`
	Complete          bool            `json:"complete"`
}
type Batch struct {
	Assets            []Asset
	RuntimeEvents     []RuntimeEvent
	LostRuntimeEvents uint64
	Processes         []Process
	Sockets           []Socket
	Interfaces        []Interface
	Mounts            []Mount
	Files             []File
	Services          []Service
	Containers        []Container
	Controls          []KernelControl
	Observations      []Observation
	Diagnostics       []Diagnostic
	Coverage          Coverage
}

func Hash(parts ...string) string {
	var framed []byte
	for _, part := range parts {
		framed = binary.LittleEndian.AppendUint64(framed, uint64(len(part)))
		framed = append(framed, part...)
	}
	h := sha256.Sum256(framed)
	return hex.EncodeToString(h[:16])
}
func Fact(subject, key, value, source, collector string, state State, at time.Time) Observation {
	return Observation{ID: Hash(subject, key, value, source, string(state)), Subject: subject, Key: key, Value: value, Source: source, Collector: collector, State: state, At: at}
}
func (s *Snapshot) Sort() {
	sort.Slice(s.Assets, func(i, j int) bool { return s.Assets[i].ID < s.Assets[j].ID })
	sort.Strings(s.Inspections)
	sort.Strings(s.RequestedRoots)
	sort.Slice(s.Interfaces, func(i, j int) bool { return s.Interfaces[i].ID < s.Interfaces[j].ID })
	sort.Slice(s.Mounts, func(i, j int) bool { return s.Mounts[i].ID < s.Mounts[j].ID })
	sort.Slice(s.Services, func(i, j int) bool {
		return s.Services[i].ID+s.Services[i].Process < s.Services[j].ID+s.Services[j].Process
	})
	sort.Slice(s.Containers, func(i, j int) bool {
		return s.Containers[i].ID+s.Containers[i].Process < s.Containers[j].ID+s.Containers[j].Process
	})
	sort.Slice(s.Controls, func(i, j int) bool { return s.Controls[i].ID < s.Controls[j].ID })
	sort.Slice(s.Coverage, func(i, j int) bool { return s.Coverage[i].Collector < s.Coverage[j].Collector })
	sort.Slice(s.Diagnostics, func(i, j int) bool {
		a, b := s.Diagnostics[i], s.Diagnostics[j]
		return a.Component+a.Target+a.Operation+a.Code+a.Cause < b.Component+b.Target+b.Operation+b.Code+b.Cause
	})
	sort.Slice(s.RuntimeEvents, func(i, j int) bool {
		a, b := s.RuntimeEvents[i], s.RuntimeEvents[j]
		if a.TimestampBootNS != b.TimestampBootNS {
			return a.TimestampBootNS < b.TimestampBootNS
		}
		return a.ID < b.ID
	})

	sort.Slice(s.Processes, func(i, j int) bool { return s.Processes[i].ID < s.Processes[j].ID })
	sort.Slice(s.Sockets, func(i, j int) bool { return s.Sockets[i].ID < s.Sockets[j].ID })
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	sort.Slice(s.Observations, func(i, j int) bool { return s.Observations[i].ID < s.Observations[j].ID })
	sort.Slice(s.Findings, func(i, j int) bool {
		if s.Findings[i].Priority != s.Findings[j].Priority {
			return s.Findings[i].Priority > s.Findings[j].Priority
		}
		return s.Findings[i].ID < s.Findings[j].ID
	})
	sort.Slice(s.Evaluations, func(i, j int) bool {
		a, b := s.Evaluations[i], s.Evaluations[j]
		return a.RuleID+a.Subject < b.RuleID+b.Subject
	})
}
