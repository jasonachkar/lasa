//go:build ignore

// Regenerate with: go run tools/schema/main.go > schemas/report-v2.schema.json
package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

var definitions = map[string]any{}

func schema(t reflect.Type) map[string]any {
	if t == reflect.TypeFor[time.Time]() {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	if t == reflect.TypeFor[domain.State]() {
		return map[string]any{"type": "string", "enum": []string{"observed", "not_observed", "unknown", "not_applicable"}}
	}
	if t == reflect.TypeFor[domain.Exposure]() {
		return map[string]any{"type": "string", "enum": []string{"confirmed", "potential", "local", "unknown"}}
	}
	switch t.Kind() {
	case reflect.Pointer:
		s := schema(t.Elem())
		return map[string]any{"anyOf": []any{s, map[string]string{"type": "null"}}}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Slice:
		return map[string]any{"type": []string{"array", "null"}, "items": schema(t.Elem())}
	case reflect.Array:
		return map[string]any{"type": "array", "items": schema(t.Elem()), "minItems": t.Len(), "maxItems": t.Len()}
	case reflect.Map:
		return map[string]any{"type": []string{"object", "null"}, "additionalProperties": schema(t.Elem())}
	case reflect.Struct:
		if _, ok := definitions[t.Name()]; !ok {
			definitions[t.Name()] = nil
			props := map[string]any{}
			required := []string{}
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")
				if tag[0] == "" || tag[0] == "-" {
					continue
				}
				s := schema(f.Type)
				if tag[0] == "schema" && t.Name() == "Snapshot" {
					s = map[string]any{"const": domain.SchemaVersion}
				}
				if tag[0] == "schema" && t.Name() == "RuntimeEvent" {
					s = map[string]any{"const": "lasa.runtime/v1"}
				}
				props[tag[0]] = s
				if len(tag) == 1 {
					required = append(required, tag[0])
				}
			}
			definitions[t.Name()] = map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": required}
		}
		return map[string]any{"$ref": "#/$defs/" + t.Name()}
	}
	panic("unsupported schema type: " + t.String())
}
func main() {
	root := schema(reflect.TypeFor[domain.Snapshot]())
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["$id"] = "https://github.com/jasonachkar/lasa/schemas/report-v2.schema.json"
	root["title"] = "LASA report v2"
	root["$defs"] = definitions
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(root); err != nil {
		panic(err)
	}
}
