package filesystem

import (
	"encoding/binary"
	"fmt"
)

// CapabilitiesEnabled validates Linux vfs_cap_data without interpreting it as host privilege.
func CapabilitiesEnabled(raw []byte) (bool, error) {
	if len(raw) < 4 {
		return false, fmt.Errorf("capability xattr truncated")
	}
	magic := binary.LittleEndian.Uint32(raw[:4])
	revision := magic >> 24
	words, size := 1, 12
	switch revision {
	case 1:
	case 2:
		words, size = 2, 20
	case 3:
		words, size = 2, 24
	default:
		return false, fmt.Errorf("unsupported capability xattr revision %d", revision)
	}
	if magic&0x00fffffe != 0 || len(raw) != size {
		return false, fmt.Errorf("invalid capability xattr flags or length")
	}
	enabled := false
	for i := 0; i < words; i++ {
		offset := 4 + 8*i
		enabled = enabled || binary.LittleEndian.Uint32(raw[offset:offset+4]) != 0 || binary.LittleEndian.Uint32(raw[offset+4:offset+8]) != 0
	}
	return enabled, nil
}
