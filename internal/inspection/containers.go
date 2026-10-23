package inspection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

type ContainerInfo struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Running bool `json:"Running"`
		Pid     int  `json:"Pid"`
	} `json:"State"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		NetworkMode    string   `json:"NetworkMode"`
		UsernsMode     string   `json:"UsernsMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapAdd         []string `json:"CapAdd"`
		SecurityOpt    []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type, Source, Destination string
		RW                        bool
	} `json:"Mounts"`
}
type RuntimeClient interface {
	Get(context.Context, string) ([]byte, error)
}
type UnixRuntime struct {
	Client    *http.Client
	Transport *http.Transport
}

func NewUnixRuntime(path string, timeout time.Duration) (*UnixRuntime, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("runtime requires an absolute UNIX socket path")
	}
	st, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if st.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("configured runtime endpoint is not a UNIX socket")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tr := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConns: 1, ResponseHeaderTimeout: timeout, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", path)
	}}
	return &UnixRuntime{Client: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Transport: tr}, nil
}
func (r *UnixRuntime) Get(ctx context.Context, path string) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, fmt.Errorf("invalid runtime API path")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://lasa-runtime"+path, nil)
	if e != nil {
		return nil, e
	}
	resp, e := r.Client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("runtime UNIX request failed: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("runtime API returned HTTP %d; response withheld", resp.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > 4<<20 {
		return nil, fmt.Errorf("runtime response exceeds 4MiB")
	}
	return raw, nil
}

var containerID = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

func apiMinor(s string) (int, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 || parts[0] != "1" {
		return 0, fmt.Errorf("unsupported Docker-compatible API version")
	}
	n, e := strconv.Atoi(parts[1])
	if e != nil || n < 24 || n > 999 {
		return 0, fmt.Errorf("unsupported Docker-compatible API version")
	}
	return n, nil
}
func (i *inspection) containers() {
	client := i.c.Runtime
	if client == nil {
		r, e := NewUnixRuntime(i.c.Config.ContainerSocket, i.c.Config.InspectionCommandTimeout)
		if e != nil {
			i.fail("connect_runtime", i.c.Config.ContainerSocket, e)
			return
		}
		defer r.Transport.CloseIdleConnections()
		client = r
	}
	raw, e := client.Get(i.ctx, "/version")
	if e != nil {
		i.fail("runtime_version", i.c.Config.ContainerSocket, e)
		return
	}
	var version struct {
		API string `json:"ApiVersion"`
		Min string `json:"MinAPIVersion"`
	}
	if json.Unmarshal(raw, &version) != nil {
		i.fail("parse_runtime_version", i.c.Config.ContainerSocket, fmt.Errorf("invalid version JSON"))
		return
	}
	api, e := apiMinor(version.API)
	if e != nil {
		i.fail("runtime_api", i.c.Config.ContainerSocket, e)
		return
	}
	if api > 50 {
		api = 50
	}
	if version.Min != "" {
		min, e := apiMinor(version.Min)
		if e != nil || min > api {
			i.unsupported(i.c.Config.ContainerSocket, "daemon requires an API newer than the supported 1.24–1.50 range")
			return
		}
	}
	prefix := "/v1." + strconv.Itoa(api)
	raw, e = client.Get(i.ctx, prefix+"/containers/json?all=1")
	if e != nil {
		i.fail("list_containers", i.c.Config.ContainerSocket, e)
		return
	}
	var list []struct {
		ID string `json:"Id"`
	}
	if json.Unmarshal(raw, &list) != nil || list == nil {
		i.fail("parse_container_list", i.c.Config.ContainerSocket, fmt.Errorf("invalid container inventory JSON"))
		return
	}
	slices.SortFunc(list, func(a, b struct {
		ID string `json:"Id"`
	}) int {
		return strings.Compare(a.ID, b.ID)
	})
	for _, item := range list {
		if !containerID.MatchString(item.ID) {
			i.unsupported("container identity", "malformed runtime container ID")
			continue
		}
		if !i.next("container " + domain.Hash(item.ID)) {
			break
		}
		raw, e := client.Get(i.ctx, prefix+"/containers/"+url.PathEscape(item.ID)+"/json")
		if e != nil {
			i.fail("inspect_container", domain.Hash(item.ID), e)
			continue
		}
		var c ContainerInfo
		if json.Unmarshal(raw, &c) != nil || c.ID != item.ID || validContainer(raw) != nil {
			i.fail("parse_container", domain.Hash(item.ID), fmt.Errorf("invalid or inconsistent container inspect response"))
			continue
		}
		i.containerFacts(c)
		i.b.Coverage.Successful++
	}
}
func (i *inspection) containerFacts(c ContainerInfo) {
	a := i.asset("runtime_container", domain.Hash(i.c.Snapshot.Host.ID, c.ID))
	refs := []string{i.fact(a, "container.runtime_state", fmt.Sprintf("running=%t privileged=%t user=%s pid_mode=%s ipc_mode=%s network_mode=%s userns_mode=%s read_only_rootfs=%t", c.State.Running, c.HostConfig.Privileged, c.Config.User, c.HostConfig.PidMode, c.HostConfig.IpcMode, c.HostConfig.NetworkMode, c.HostConfig.UsernsMode, c.HostConfig.ReadonlyRootfs), i.c.Config.ContainerSocket, domain.Observed)}
	socket, sensitive, unconfined := false, false, false
	for _, opt := range c.HostConfig.SecurityOpt {
		if slices.Contains([]string{"seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined", "apparmor:unconfined"}, opt) {
			unconfined = true
			refs = append(refs, i.fact(a, "container.disabled_confinement", opt, a.Label, domain.Observed))
		}
	}
	for _, m := range c.Mounts {
		refs = append(refs, i.fact(a, "container.mount", fmt.Sprintf("type=%s source=%s target=%s writable=%t", m.Type, m.Source, m.Destination, m.RW), a.Label, domain.Observed))
		base := filepath.Base(m.Source)
		socket = socket || slices.Contains([]string{"docker.sock", "containerd.sock", "crio.sock", "podman.sock"}, base)
		sensitive = sensitive || m.Type == "bind" && m.RW && slices.Contains([]string{"/", "/etc", "/proc", "/sys", "/root", "/run", "/var/run", "/var/lib/docker", "/var/lib/containerd"}, filepath.Clean(m.Source))
	}
	dangerous := false
	for _, cap := range c.HostConfig.CapAdd {
		cap = strings.TrimPrefix(cap, "CAP_")
		dangerous = dangerous || slices.Contains([]string{"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "DAC_READ_SEARCH"}, cap)
		refs = append(refs, i.fact(a, "container.added_capability", cap, a.Label, domain.Observed))
	}
	i.risk(a, "containers.privileged", c.State.Running && c.HostConfig.Privileged, domain.Observed, refs...)
	i.risk(a, "containers.host_pid", c.State.Running && c.HostConfig.PidMode == "host", domain.Observed, refs...)
	i.risk(a, "containers.runtime_socket", c.State.Running && socket, domain.Observed, refs...)
	i.risk(a, "containers.sensitive_mount", c.State.Running && sensitive, domain.Observed, refs...)
	i.risk(a, "containers.unconfined_capabilities", c.State.Running && dangerous && unconfined, domain.Observed, refs...)
}

func validContainer(raw []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return fmt.Errorf("invalid container object")
	}
	for group, keys := range map[string][]string{"State": {"Running", "Pid"}, "Config": {"User"}, "HostConfig": {"Privileged", "PidMode", "IpcMode", "NetworkMode", "UsernsMode", "ReadonlyRootfs", "CapAdd", "SecurityOpt"}} {
		var values map[string]json.RawMessage
		if json.Unmarshal(fields[group], &values) != nil || values == nil {
			return fmt.Errorf("missing runtime configuration group %s", group)
		}
		for _, key := range keys {
			if value, ok := values[key]; !ok || string(value) == "null" && key != "CapAdd" && key != "SecurityOpt" {
				return fmt.Errorf("missing runtime configuration field %s/%s", group, key)
			}
		}
	}
	var mounts []json.RawMessage
	if json.Unmarshal(fields["Mounts"], &mounts) != nil || mounts == nil || len(mounts) > 4096 {
		return fmt.Errorf("missing, invalid or oversized runtime mount list")
	}
	return nil
}
