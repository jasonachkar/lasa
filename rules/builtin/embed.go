// Package builtin contains the reviewed, local-only rule pack.
package builtin

import _ "embed"

//go:embed rules.yaml
var YAML []byte
