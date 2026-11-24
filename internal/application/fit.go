package application

import (
	"fmt"
	"path/filepath"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
)

// fitAttempts bounds how often the analysis is repeated while reducing scope.
const fitAttempts = 6

// fitExport keeps a scan exportable. Reports above the export limit cannot
// be written or read back, so instead of discarding the whole scan the file
// metadata scope is reduced deterministically until the JSON export fits.
// Files that findings or derived facts depend on are always kept; the rest
// are kept in collection order, which is breadth-first from each root. The
// omission is recorded as incomplete filesystem coverage and a diagnostic,
// so the reduced scope can never be mistaken for a clean result.
func (e Engine) fitExport(collected, analyzed domain.Snapshot) (domain.Snapshot, error) {
	limit := e.ExportLimit
	if limit <= 0 {
		limit = report.MaxInput
	}
	// Leave headroom for suppression metadata applied after the scan.
	budget := limit - limit/16
	size, err := exportSize(analyzed)
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
	keep := len(droppable)
	for attempt := 0; attempt < fitAttempts && keep > 0; attempt++ {
		// File metadata dominates report size, so scale the kept share by the
		// overshoot, with a margin that shrinks the scope further on retries.
		keep = int(float64(keep) * float64(budget) / float64(size) * 0.9)
		candidate := reduceFiles(collected, protected, droppable[:keep], len(collected.Files))
		if err = e.analyze(&candidate); err != nil {
			return analyzed, err
		}
		if size, err = exportSize(candidate); err != nil {
			return analyzed, err
		}
		if size <= budget {
			return candidate, nil
		}
	}
	// Nothing reducible remains (for example a process-dominated report);
	// return the analysis unchanged so export reports the limit explicitly.
	return analyzed, nil
}

func exportSize(s domain.Snapshot) (int, error) {
	raw, err := report.Marshal(s)
	return len(raw), err
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
	for _, f := range collected.Files {
		if protected[f.ID] || keep[f.ID] {
			s.Files = append(s.Files, f)
		}
	}
	omitted := total - len(s.Files)
	present := map[string]bool{}
	for _, f := range s.Files {
		present[f.ID] = true
	}
	removed := map[string]bool{}
	for _, f := range collected.Files {
		if !present[f.ID] {
			removed[f.ID] = true
		}
	}
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
