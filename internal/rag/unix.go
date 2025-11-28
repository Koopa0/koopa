//go:build unix

package rag

import (
	"os"
	"syscall"
)

// getDeviceID extracts the device ID from file info on Unix systems.
// This is used for security monitoring to detect cross-device hardlink attacks.
// Returns 0, false if the device ID cannot be determined.
func getDeviceID(info os.FileInfo) (int64, bool) {
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		// syscall.Stat_t.Dev is uint64 on most Unix systems;
		// widening to int64 is safe: device IDs are typically small values
		// and int64 can represent all practical device IDs without overflow.
		// #nosec G115 -- Dev is a device identifier, not arbitrary uint64; overflow not possible in practice
		return int64(sys.Dev), true
	}
	return 0, false
}

// getHardlinkCount returns the number of hard links to a file on Unix systems.
// Files with nlink > 1 have multiple names (hardlinks) pointing to the same inode.
// Returns 0, false if the count cannot be determined.
func getHardlinkCount(info os.FileInfo) (uint64, bool) {
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(sys.Nlink), true
	}
	return 0, false
}
