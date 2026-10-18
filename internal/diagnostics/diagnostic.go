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
func Limit(component, target string) domain.Diagnostic {
	return domain.Diagnostic{Code: "RESOURCE_LIMIT", Component: component, Operation: "enumerate", Target: target, Cause: "Configured resource budget reached", Impact: "Uninspected assets remain unknown; coverage is incomplete.", Remediation: "Narrow the scan scope or raise the documented budget deliberately.", Recoverable: true}
}
