package domain

import "reflect"

// EmptyCollections replaces nil slices and maps reachable from v with empty
// ones, so JSON consumers always receive [] or {} instead of null for an
// empty collection. v must be a non-nil pointer.
func EmptyCollections(v any) {
	fill(reflect.ValueOf(v))
}

func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			fill(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			if v.CanSet() {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
			return
		}
		if !elementsMayHoldCollections(v.Type().Elem()) {
			return
		}
		for i := 0; i < v.Len(); i++ {
			fill(v.Index(i))
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fill(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.MakeMap(v.Type()))
		}
	}
}

// elementsMayHoldCollections avoids walking large slices of scalars.
func elementsMayHoldCollections(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct, reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Array, reflect.Map:
		return true
	}
	return false
}
