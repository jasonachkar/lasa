//go:build linux

// Package ebpf is an optional bounded metadata observer. Static scans never load BPF.
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	"golang.org/x/sys/unix"
)

type Collector struct {
	Duration  time.Duration
	MaxEvents int
	BootID    string
}

func (c Collector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "ebpf", Version: "1", Features: []string{"BTF CO-RE", "ring buffer", "tracepoints"}, OptionalPrivileges: []string{"authorized CAP_BPF and CAP_PERFMON in initial user namespace, subject to kernel policy; adequate memlock on older kernels"}}
}

type wire struct {
	Timestamp uint64
	Start     uint64
	PID       uint32
	TID       uint32
	UID       uint32
	PPID      uint32
	Kind      uint32
	Result    int32
	Flags     uint64
	Family    uint16
	Port      uint16
	Address   [16]byte
	Comm      [16]byte
	Padding   [4]byte
}

func decode(raw []byte, boot string) (domain.RuntimeEvent, error) {
	var w wire
	if len(raw) != 88 {
		return domain.RuntimeEvent{}, fmt.Errorf("runtime event ABI length %d (need 88)", len(raw))
	}
	if e := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &w); e != nil {
		return domain.RuntimeEvent{}, e
	}
	kinds := map[uint32]string{1: "process_exec", 2: "connect_attempt", 3: "bind_attempt", 4: "accepted_connection", 5: "unshare_succeeded"}
	kind, ok := kinds[w.Kind]
	if !ok {
		return domain.RuntimeEvent{}, fmt.Errorf("unknown runtime event kind %d", w.Kind)
	}
	address := ""
	if w.Family == 2 {
		address = netip.AddrFrom4([4]byte(w.Address[:4])).String()
	} else if w.Family == 10 {
		address = netip.AddrFrom16(w.Address).String()
	} else if w.Family != 0 {
		return domain.RuntimeEvent{}, fmt.Errorf("unsupported event family %d", w.Family)
	}
	return domain.RuntimeEvent{Schema: "lasa.runtime/v1", ID: domain.Hash(boot, fmt.Sprint(w.Timestamp, w.PID, w.TID, w.Kind)), Kind: kind, BootID: boot, TimestampBootNS: w.Timestamp, StartBootNS: w.Start, PID: w.PID, TID: w.TID, UID: w.UID, PPID: w.PPID, Command: strings.TrimRight(string(w.Comm[:]), "\x00"), Address: address, Port: w.Port, Result: w.Result, Flags: w.Flags}, nil
}
func (c Collector) Collect(parent context.Context) (b domain.Batch) {
	b = collector.Begin("ebpf", "optional bounded event window; process exec, IP connect/bind attempts, successful accept and unshare; no listen-success, clone or payload capture")
	defer collector.Finish(&b)
	fail := func(code, op, target string, e error) {
		d := diagnostics.New("ebpf", op, target, e)
		d.Code = code
		d.Requirement = "BTF, tracefs, supported BPF helpers/maps and authorized BPF/perf permissions"
		d.Remediation = "Use a supported Linux host with BTF and tracefs exposed; authorize CAP_BPF/CAP_PERFMON according to host policy and an adequate memory-lock limit. Do not change host security policy solely to silence this diagnostic."
		var ve *bpf.VerifierError
		if errors.As(e, &ve) {
			d.Code = "EBPF_VERIFIER_REJECTED"
			d.Cause = fmt.Sprintf("%+v", ve)
		} else if errors.Is(e, os.ErrPermission) || errors.Is(e, unix.EPERM) {
			d.Code = "EBPF_PERMISSION_DENIED"
		}
		b.Diagnostics = append(b.Diagnostics, d)
		b.Coverage.Inconclusive++
	}
	if c.Duration <= 0 || c.Duration > 10*time.Minute || c.MaxEvents < 1 || c.MaxEvents > 65536 {
		fail("CONFIG_INVALID", "validate", "sensor budget", fmt.Errorf("invalid observation window or event budget"))
		return
	}
	ctx, cancel := context.WithTimeout(parent, c.Duration)
	defer cancel()
	if ctx.Err() != nil {
		fail("SCAN_CANCELLED", "start", "sensor", ctx.Err())
		return
	}
	kernel, e := btf.LoadKernelSpec()
	if e != nil {
		fail("BTF_UNAVAILABLE", "load", "kernel BTF", e)
		return
	}
	for _, feature := range []struct {
		name  string
		check func() error
	}{{"tracepoint", func() error { return features.HaveProgramType(bpf.TracePoint) }}, {"ringbuf", func() error { return features.HaveMapType(bpf.RingBuf) }}} {
		if e = feature.check(); e != nil {
			fail("EBPF_UNSUPPORTED", "probe", feature.name, e)
			return
		}
	}
	var objects sensorObjects
	if e = loadSensorObjects(&objects, &bpf.CollectionOptions{Programs: bpf.ProgramOptions{KernelTypes: kernel}}); e != nil {
		fail("EBPF_LOAD_FAILED", "load", "embedded sensor", e)
		return
	}
	defer func() {
		if e := objects.Close(); e != nil {
			fail("EBPF_CLOSE_FAILED", "close", "sensor objects", e)
		}
	}()
	hooks := []struct {
		group, name string
		p           *bpf.Program
	}{{"sched", "sched_process_exec", objects.ProcessExec}, {"syscalls", "sys_enter_connect", objects.ConnectAttempt}, {"syscalls", "sys_enter_bind", objects.BindAttempt}, {"syscalls", "sys_exit_accept4", objects.Accepted4}, {"syscalls", "sys_exit_accept", objects.Accepted}, {"syscalls", "sys_enter_unshare", objects.NamespaceEnter}, {"syscalls", "sys_exit_unshare", objects.NamespaceExit}}
	var links []link.Link
	defer func() {
		for _, l := range links {
			if e := l.Close(); e != nil {
				fail("EBPF_CLOSE_FAILED", "detach", "tracepoint", e)
			}
		}
	}()
	for _, h := range hooks {
		b.Coverage.Attempted++
		l, e := link.Tracepoint(h.group, h.name, h.p, nil)
		if e != nil {
			fail("TRACEPOINT_UNAVAILABLE", "attach", h.group+"/"+h.name, e)
			continue
		}
		links = append(links, l)
		b.Coverage.Successful++
	}
	if len(links) == 0 {
		return
	}
	reader, e := ringbuf.NewReader(objects.Events)
	if e != nil {
		fail("EBPF_READ_FAILED", "open", "ring buffer", e)
		return
	}
	defer func() {
		if e := reader.Close(); e != nil {
			fail("EBPF_CLOSE_FAILED", "close", "ring buffer", e)
		}
	}()
	for ctx.Err() == nil {
		reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
		record, e := reader.Read()
		if errors.Is(e, os.ErrDeadlineExceeded) {
			continue
		}
		if e != nil {
			fail("EBPF_READ_FAILED", "read", "ring buffer", e)
			break
		}
		event, e := decode(record.RawSample, c.BootID)
		if e != nil {
			fail("EBPF_EVENT_INVALID", "decode", "ring buffer event", e)
			continue
		}
		if len(b.RuntimeEvents) >= c.MaxEvents {
			b.LostRuntimeEvents++
			continue
		}
		b.RuntimeEvents = append(b.RuntimeEvents, event)
	}
	if parent.Err() != nil {
		fail("SCAN_CANCELLED", "observe", "sensor window", parent.Err())
	}
	var lost []uint64
	if e = objects.Dropped.Lookup(uint32(0), &lost); e != nil {
		fail("EBPF_COUNTER_UNREADABLE", "read", "kernel event drops", e)
	} else {
		for _, n := range lost {
			b.LostRuntimeEvents += n
		}
	}
	if b.LostRuntimeEvents > 0 {
		fail("EBPF_EVENTS_LOST", "observe", "sensor window", fmt.Errorf("%d runtime events were lost to backpressure or the configured retention budget", b.LostRuntimeEvents))
	}
	return
}
