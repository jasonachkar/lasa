// Package container interprets hints; it never equates a hint with a verified container boundary.
package container

import "strings"

func Hint(cgroups []string) string {
	for _, g := range cgroups {
		for _, name := range []string{"docker", "kubepods", "containerd", "libpod", "lxc"} {
			if strings.Contains(g, name) {
				return name
			}
		}
	}
	return ""
}
func Service(cgroups []string) string {
	for _, g := range cgroups {
		for _, s := range strings.Split(g, "/") {
			if strings.HasSuffix(s, ".service") && !strings.Contains(s, "@") && len(s) <= 256 {
				return s
			}
		}
	}
	return ""
}
