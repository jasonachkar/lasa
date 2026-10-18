// Package collector defines bounded collection contracts shared by Linux adapters.
package collector

import (
	"context"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

type Descriptor struct {
	ID                 string
	Version            string
	Features           []string
	OptionalPrivileges []string
}
type Collector interface {
	Descriptor() Descriptor
	Collect(context.Context) domain.Batch
}

func Begin(id, scope string) domain.Batch {
	return domain.Batch{Coverage: domain.Coverage{Collector: id, Version: "1", Started: time.Now().UTC(), Complete: true, Scope: scope}}
}
func Finish(b *domain.Batch) {
	b.Coverage.Completed = time.Now().UTC()
	if b.Coverage.Inconclusive > 0 || b.Coverage.Unsupported > 0 || b.Coverage.Skipped > 0 {
		b.Coverage.Complete = false
	}
}
