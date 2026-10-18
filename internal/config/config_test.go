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
