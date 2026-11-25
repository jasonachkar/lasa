package application

import (
	"fmt"
	"path/filepath"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
)

// fitAttempts bounds re-analysis when the first reduced scope still does not
// fit, which only happens when per-file estimates are off.
const fitAttempts = 4

// fitExport keeps a scan exportable. Reports above the export limit cannot
// be written or read back, so instead of discarding the whole scan the file
// metadata scope is reduced deterministically until the JSON export fits.
// Files that findings or derived facts depend on are always kept; the rest
// are kept in collection order, which is breadth-first from each root. The
// omission is recorded as incomplete filesystem coverage and a diagnostic,
// so the reduced scope can never be mistaken for a clean result.
//
// Sizes are computed exactly without building the document, and the scope is
// chosen from each file's measured contribution, so a reduction normally
// needs a single additional analysis and bounded memory.
func (e Engine) fitExport(collected, analyzed domain.Snapshot) (domain.Snapshot, error) {
	limit := e.ExportLimit
	if limit <= 0 {
		limit = report.MaxInput
	}
	// Leave headroom for suppression metadata applied after the scan.
	budget := limit - limit/16
	size, err := report.Size(analyzed)
	if err != nil || size <= budget {
		return analyzed, err
	}
	protected := protectedFiles(collected, analyzed)
	var droppable []domain.File
	for _, f := range collected.Files {
		if !protected[f.ID] {
			droppable = append(droppable, f)
		}
	}
	costs, err := fileCosts(analyzed, droppable)
	if err != nil {
		return analyzed, err
	}
	var droppableBytes int
	for _, c := range costs {
		droppableBytes += c
	}
	// Room for the reduction diagnostic and changed coverage counters.
	const slack = 4 << 10
	room := budget - (size - droppableBytes) - slack
	keep := 0
	for keep < len(droppable) && costs[keep] <= room {
		room -= costs[keep]
		keep++
	}
	// The full analysis is no longer needed; let it be reclaimed before the
	// reduced scope is analyzed.
	analyzed = domain.Snapshot{}
	var candidate domain.Snapshot
	for attempt := 0; attempt < fitAttempts; attempt++ {
		candidate = reduceFiles(collected, protected, droppable[:keep], len(collected.Files))
		if err = e.analyze(&candidate); err != nil {
			return candidate, err
		}
		if size, err = report.Size(candidate); err != nil || size <= budget || keep == 0 {
			// Nothing reducible remains when keep is zero (for example a
			// process-dominated report); export then reports the limit.
			return candidate, err
		}
		keep = keep * 9 / 10
	}
	return candidate, nil
}

// fileCosts returns, for each droppable file in order, the bytes it adds to
// the export: its file entry, graph node, observations and rule evaluations.
func fileCosts(s domain.Snapshot, droppable []domain.File) ([]int, error) {
	index := make(map[string]int, len(droppable))
	for i, f := range droppable {
		index[f.ID] = i
	}
	costs := make([]int, len(droppable))
	add := func(slice any, subject func(int) string) error {
		sizes, err := report.ElementSizes(slice)
		if err != nil {
			return err
		}
		for i, n := range sizes {
			if j, ok := index[subject(i)]; ok {
				costs[j] += n
			}
		}
		return nil
	}
	for _, step := range []func() error{
		func() error { return add(s.Files, func(i int) string { return s.Files[i].ID }) },
		func() error { return add(s.Observations, func(i int) string { return s.Observations[i].Subject }) },
		func() error { return add(s.Evaluations, func(i int) string { return s.Evaluations[i].Subject }) },
		func() error { return add(s.Graph.Nodes, func(i int) string { return s.Graph.Nodes[i].ID }) },
	} {
		if err := step(); err != nil {
			return nil, err
		}
	}
	return costs, nil
}

// protectedFiles returns files whose removal would change findings or the
// facts derived for other subjects: finding subjects, their ancestors (used
// for writable-parent facts) and executables of observed processes.
func protectedFiles(collected, analyzed domain.Snapshot) map[string]bool {
	subjects := map[string]bool{}
	for _, f := range analyzed.Findings {
		for _, id := range append([]string{f.Subject}, f.Subjects...) {
			subjects[id] = true
		}
	}
	executables := map[string]bool{}
	for _, p := range collected.Processes {
		executables[p.Executable] = true
	}
	byPath := map[string]domain.File{}
	for _, f := range collected.Files {
		byPath[f.Path] = f
	}
	protected := map[string]bool{}
	for _, f := range collected.Files {
		if !subjects[f.ID] && !executables[f.Path] {
			continue
		}
		protected[f.ID] = true
		for p := filepath.Dir(f.Path); p != "/" && p != "."; p = filepath.Dir(p) {
			if parent, ok := byPath[p]; ok {
				protected[parent.ID] = true
			}
		}
	}
	return protected
}

// reduceFiles builds a collected snapshot restricted to protected and kept
// files, removing the evidence that belonged to omitted files.
func reduceFiles(collected domain.Snapshot, protected map[string]bool, kept []domain.File, total int) domain.Snapshot {
	s := cloneCollected(collected)
	keep := map[string]bool{}
	for _, f := range kept {
		keep[f.ID] = true
	}
	s.Files = s.Files[:0]
	removed := map[string]bool{}
	for _, f := range collected.Files {
		if protected[f.ID] || keep[f.ID] {
			s.Files = append(s.Files, f)
		} else {
			removed[f.ID] = true
		}
	}
	omitted := total - len(s.Files)
	s.Observations = s.Observations[:0]
	for _, o := range collected.Observations {
		if !removed[o.Subject] {
			s.Observations = append(s.Observations, o)
		}
	}
	for i := range s.Coverage {
		if s.Coverage[i].Collector == "filesystem" {
			s.Coverage[i].Skipped += omitted
			s.Coverage[i].Complete = false
		}
	}
	s.Complete = false
	s.Diagnostics = append(s.Diagnostics, domain.Diagnostic{
		Code: "RESOURCE_LIMIT", Component: "report", Operation: "fit_export", Target: "file metadata",
		Cause:       fmt.Sprintf("%d of %d file metadata entries were omitted to keep the report under the %d MiB export limit", omitted, total, report.MaxInput>>20),
		Impact:      "Omitted files were not evaluated; findings on them can be neither established nor resolved.",
		Remediation: "Narrow --roots or lower --max-files so the complete scope fits in one report.",
		Recoverable: true,
	})
	return s
}
