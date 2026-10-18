package container

import (
	"strings"
	"testing"
)

func TestHints(t *testing.T) {
	if Hint([]string{"0::/docker/abc"}) != "docker" {
		t.Fatal("hint missing")
	}
	if Hint([]string{"0::/"}) != "" {
		t.Fatal("invented container")
	}
	if Service([]string{"0::/system.slice/sshd.service"}) != "sshd.service" {
		t.Fatal("service missing")
	}
}
func TestOpaqueIdentifierRedaction(t *testing.T) {
	out, changed := Redact([]string{"0::/docker/abcdef0123456789/system.slice/sshd.service"})
	if !changed || strings.Contains(out[0], "abcdef0123456789") || Hint(out) != "docker" || Service(out) != "sshd.service" {
		t.Fatal(out)
	}
	again, _ := Redact([]string{"0::/docker/abcdef0123456789/system.slice/sshd.service"})
	if out[0] != again[0] {
		t.Fatal("redaction not stable")
	}
}
