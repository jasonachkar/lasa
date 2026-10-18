package container

import (
	"regexp"

	"github.com/jasonachkar/lasa/internal/domain"
)

var opaqueID = regexp.MustCompile(`[0-9a-fA-F]{12,}`)

// Redact replaces long hexadecimal cgroup identifiers, preserving runtime/service hints.
func Redact(paths []string) ([]string, bool) {
	out := make([]string, len(paths))
	changed := false
	for i, p := range paths {
		out[i] = opaqueID.ReplaceAllStringFunc(p, func(id string) string { changed = true; return "id-" + domain.Hash("lasa.cgroup/v1", id)[:12] })
	}
	return out, changed
}
