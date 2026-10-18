package kernel

import (
	"context"
	"io/fs"
	"testing"
)

type unavailable struct{}

func (unavailable) Read(string) ([]byte, error)               { return nil, fs.ErrPermission }
func (unavailable) Readlink(string) (string, error)           { return "", fs.ErrPermission }
func (unavailable) Names(string, int) ([]string, bool, error) { return nil, false, fs.ErrPermission }
func TestUnknownControls(t *testing.T) {
	b := (Collector{Proc: unavailable{}, Sys: unavailable{}, HostID: "h"}).Collect(context.Background())
	if b.Coverage.Complete || len(b.Controls) != 12 {
		t.Fatal("controls not represented")
	}
	for _, o := range b.Observations {
		if o.State != "unknown" {
			t.Fatal("inaccessible control deemed secure")
		}
	}
}
