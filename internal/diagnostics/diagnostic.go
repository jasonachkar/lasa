package diagnostics

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/jasonachkar/lasa/internal/domain"
)

func New(component, operation, target string, err error) domain.Diagnostic {
	d := domain.Diagnostic{Code: "COLLECTION_FAILED", Component: component, Operation: operation, Target: target, Cause: err.Error(), Impact: "Evidence for this target is unknown; dependent rules cannot confirm or resolve an issue.", Remediation: "Inspect the target and scanner scope; rerun after resolving the reported cause.", Recoverable: true}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		d.Errno = int(errno)
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		d.Code = "SCAN_CANCELLED"
		d.Remediation = "Increase --timeout if needed, or rerun without cancellation."
	case errors.Is(err, os.ErrPermission):
		d.Code = "PERMISSION_DENIED"
		d.Remediation = "Check ownership, procfs hidepid and namespace scope. Use an explicitly authorized host-context deep scan if appropriate; no automatic elevation is performed."
	case errors.Is(err, os.ErrNotExist):
		d.Code = "NOT_FOUND"
		d.Remediation = "Check the path and namespace visibility; absent metadata remains unknown."
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.EXDEV):
		d.Code = "UNSAFE_PATH"
		d.Remediation = "Use an explicit scope without symlinks or paths outside its root."
	}
	return d
}

// Expected codes describe established absences rather than visibility gaps.
// They are counted as unsupported work, which does not make coverage
// incomplete, and renderers present them separately from collection gaps.
const (
	CodeNotPresent         = "NOT_PRESENT"
	CodeSymlinkNotFollowed = "SYMLINK_NOT_FOLLOWED"
	CodeNotSupported       = "NOT_SUPPORTED_BY_KERNEL"
)

// IsExpected reports whether a diagnostic code records an established,
// policy- or platform-defined absence instead of missing evidence.
func IsExpected(code string) bool {
	switch code {
	case CodeNotPresent, CodeSymlinkNotFollowed, CodeNotSupported:
		return true
	}
	return false
}

// Expected records an established absence with a code-specific explanation.
func Expected(code, component, operation, target, cause, impact, remediation string) domain.Diagnostic {
	return domain.Diagnostic{Code: code, Component: component, Operation: operation, Target: target, Cause: cause, Impact: impact, Remediation: remediation, Recoverable: true}
}

func Limit(component, target string) domain.Diagnostic {
	return domain.Diagnostic{Code: "RESOURCE_LIMIT", Component: component, Operation: "enumerate", Target: target, Cause: "Configured resource budget reached", Impact: "Uninspected assets remain unknown; coverage is incomplete.", Remediation: "Narrow the scan scope or raise the documented budget deliberately.", Recoverable: true}
}
