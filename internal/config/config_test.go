package config

import (
	"testing"
	"time"
)

func TestValidation(t *testing.T) {
	c := Default()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, f := range []func(*Config){func(c *Config) { c.Workers = 0 }, func(c *Config) { c.Roots = []string{"/"} }, func(c *Config) { c.Timeout = -time.Second }, func(c *Config) { c.Profile = "oops" }} {
		c := Default()
		f(&c)
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

func TestInspectionScopeAndInputs(t *testing.T) {
	a, b := Default(), Default()
	a.Inspect = []string{"all"}
	b.Inspect = append([]string(nil), InspectionModules...)
	if a.ScopeID() != b.ScopeID() {
		t.Fatal("equivalent module scopes differ")
	}
	b.Roots = []string{"/opt/only"}
	if a.ScopeID() == b.ScopeID() {
		t.Fatal("narrowed filesystem scope was not recorded")
	}
	for _, modify := range []func(*Config){func(c *Config) { c.Inspect = []string{"unknown"} }, func(c *Config) { c.Inspect = []string{"all", "ssh"} }, func(c *Config) { c.NetworkSource = "not-an-address" }, func(c *Config) { c.SSHContexts = []string{"user=root,host=x,addr=bad,laddr=127.0.0.1,lport=22"} }, func(c *Config) { c.SSHContexts = []string{"user=root,host=x,addr=127.0.0.1,laddr=127.0.0.1,lport=0"} }, func(c *Config) { c.Inspect = []string{"ssh"}; c.MaxInspectionItems = 0 }} {
		c := Default()
		modify(&c)
		if c.Validate() == nil {
			t.Fatal("invalid inspection config accepted", c)
		}
	}
}
