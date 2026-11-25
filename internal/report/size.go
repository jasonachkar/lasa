package report

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/jasonachkar/lasa/internal/domain"
)

// Size returns exactly len(Marshal(s)) without building the document. Each
// top-level slice element is encoded on its own, so peak memory is one
// element rather than the whole report. It assumes s is already sorted and
// normalized, as Marshal does before encoding.
func Size(s domain.Snapshot) (int, error) {
	domain.EmptyCollections(&s)
	v := reflect.ValueOf(s)
	t := v.Type()
	total := len("{\n") + len("}")
	fields := 0
	for i := 0; i < t.NumField(); i++ {
		name, ok := jsonName(t.Field(i))
		if !ok {
			continue
		}
		if fields > 0 {
			total += len(",\n")
		}
		fields++
		n, e := valueSize(v.Field(i))
		if e != nil {
			return 0, e
		}
		key, _ := json.Marshal(name)
		total += len("  ") + len(key) + len(": ") + n
	}
	if fields > 0 {
		total += len("\n")
	}
	return total, nil
}

// ElementSizes returns the encoded size each element contributes to a
// top-level slice field of the report, including its indentation and
// separator, keyed by index.
func ElementSizes(slice any) ([]int, error) {
	v := reflect.ValueOf(slice)
	out := make([]int, v.Len())
	for i := 0; i < v.Len(); i++ {
		raw, e := json.MarshalIndent(v.Index(i).Interface(), "    ", "  ")
		if e != nil {
			return nil, e
		}
		out[i] = len("    ") + len(raw) + len(",\n")
	}
	return out, nil
}

// valueSize is the encoded size of a top-level field value at indent depth 1.
func valueSize(v reflect.Value) (int, error) {
	if v.Kind() != reflect.Slice || v.Len() == 0 {
		raw, e := json.MarshalIndent(v.Interface(), "  ", "  ")
		return len(raw), e
	}
	elements, e := ElementSizes(v.Interface())
	if e != nil {
		return 0, e
	}
	n := len("[\n") + len("  ]") - len(",")
	for _, size := range elements {
		n += size
	}
	return n, nil
}

func jsonName(f reflect.StructField) (string, bool) {
	if !f.IsExported() {
		return "", false
	}
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	if name, _, _ := strings.Cut(tag, ","); name != "" {
		return name, true
	}
	return f.Name, true
}
