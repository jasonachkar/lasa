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

// Finish closes a batch. Skipped (budget or cancellation) and inconclusive
// (inaccessible or failed) work leaves the declared scope incompletely
// observed. Unsupported work is an expected absence that was established
// rather than missed: an entry excluded by documented policy, such as a
// symbolic link, or a control that does not exist on this kernel. It is
// reported, but it does not make collection incomplete.
func Finish(b *domain.Batch) {
	b.Coverage.Completed = time.Now().UTC()
	if b.Coverage.Inconclusive > 0 || b.Coverage.Skipped > 0 {
		b.Coverage.Complete = false
	}
}
