package access

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func aclRaw(entries ...ACLEntry) []byte {
	out := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		out = binary.LittleEndian.AppendUint16(out, e.Tag)
		out = binary.LittleEndian.AppendUint16(out, e.Perm)
		out = binary.LittleEndian.AppendUint32(out, e.ID)
	}
	return out
}
func TestACLIdentityAndMasks(t *testing.T) {
	none := ^uint32(0)
	entries := []ACLEntry{{1, 6, none}, {2, 6, 1001}, {4, 4, none}, {8, 6, 44}, {16, 4, none}, {32, 2, none}}
	raw := aclRaw(entries...)
	parsed, e := ParseACL(raw)
	if e != nil {
		t.Fatal(e)
	}
	m := Metadata{UID: 1000, GID: 30, ACL: parsed}
	cases := []struct {
		a    Account
		want uint16
	}{{Account{UID: 1000}, 6}, {Account{UID: 1001}, 4}, {Account{UID: 2000, GID: 44}, 4}, {Account{UID: 2000, GID: 99}, 2}, {Account{UID: 2000, GID: 30, Groups: []uint32{44}}, 4}}
	for _, tt := range cases {
		if got := Permissions(m, tt.a); got != tt.want {
			t.Fatalf("uid=%d got %d want %d", tt.a.UID, got, tt.want)
		}
	}
	for _, raw := range [][]byte{nil, {2, 0, 0}, aclRaw(ACLEntry{1, 8, none}), aclRaw(ACLEntry{1, 7, none}, ACLEntry{4, 7, none}, ACLEntry{32, 7, none}, ACLEntry{2, 7, 1001}), aclRaw(ACLEntry{1, 7, none}, ACLEntry{1, 7, none}, ACLEntry{4, 7, none}, ACLEntry{32, 7, none})} {
		if _, e := ParseACL(raw); e == nil {
			t.Fatalf("invalid ACL accepted: %x", raw)
		}
	}
}
func TestAccountsDoNotRetainPasswordOrGecos(t *testing.T) {
	accounts, e := Accounts([]byte("root:x:0:0:secret:/root:/bin/sh\ndeploy:SECRET:1001:1001:private:/home/deploy:/bin/bash\n"), []byte("deploy:x:1001:\nops:x:44:deploy\n"))
	if e != nil {
		t.Fatal(e)
	}
	if len(accounts) != 2 || accounts[0].Name != "deploy" || !slices.Contains(accounts[0].Groups, uint32(44)) {
		t.Fatalf("%+v", accounts)
	}
	if _, e := Accounts([]byte("invalid"), nil); e == nil {
		t.Fatal("malformed passwd accepted")
	}
}
func TestRealPathTraversalSymlinksAndStickyDirectory(t *testing.T) {
	dir, e := os.MkdirTemp("", "lasa-access-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "job")
	if e := os.WriteFile(path, []byte("never read this secret"), 0644); e != nil {
		t.Fatal(e)
	}
	owner := uint32(os.Getuid())
	stranger := owner + 10000
	if stranger == 0 {
		stranger = 65534
	}
	a := []Account{{Name: "stranger", UID: stranger, GID: stranger}}
	r, e := EvaluatePath(context.Background(), path, a)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Writers) != 0 {
		t.Fatal("protected file writable", r)
	}
	if e := os.Chmod(path, 0666); e != nil {
		t.Fatal(e)
	}
	r, e = EvaluatePath(context.Background(), path, a)
	if e != nil || len(r.Writers) != 1 {
		t.Fatalf("world write missing: %+v %v", r, e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, 0777); e != nil {
		t.Fatal(e)
	}
	r, e = EvaluatePath(context.Background(), path, a)
	if e != nil || len(r.Writers) != 1 {
		t.Fatalf("replacement missing %+v %v", r, e)
	}
	if e := os.Chmod(dir, os.ModeSticky|0777); e != nil {
		t.Fatal(e)
	}
	r, e = EvaluatePath(context.Background(), path, a)
	if e != nil || len(r.Writers) != 0 {
		t.Fatalf("sticky bypass %+v %v", r, e)
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	r, e = EvaluatePath(context.Background(), link, a)
	if e != nil || r.Target != path || len(r.Writers) != 0 {
		t.Fatalf("symlink metadata %+v %v", r, e)
	}
	loop := filepath.Join(dir, "loop")
	if e := os.Symlink(loop, loop); e != nil {
		t.Fatal(e)
	}
	if _, e := EvaluatePath(context.Background(), loop, a); e == nil {
		t.Fatal("symlink loop accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := EvaluatePath(ctx, path, a); e == nil {
		t.Fatal("cancel ignored")
	}
}
func TestModeOwnerClassDoesNotFallThrough(t *testing.T) {
	m := Metadata{Mode: unix.S_IFREG | 0006, UID: 1001, GID: 1002}
	if Permissions(m, Account{UID: 1001, GID: 1002}) != 0 {
		t.Fatal("owner fell through to other class")
	}
	m.Mode = unix.S_IFREG | 0060
	if Permissions(m, Account{UID: 1003, GID: 1002}) != 6 {
		t.Fatal("primary group was ignored")
	}
}
func FuzzACL(f *testing.F) {
	f.Add(aclRaw(ACLEntry{1, 7, ^uint32(0)}, ACLEntry{4, 5, ^uint32(0)}, ACLEntry{32, 5, ^uint32(0)}))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			return
		}
		_, _ = ParseACL(raw)
	})
}
