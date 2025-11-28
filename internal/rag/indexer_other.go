//go:build !unix

package rag

import "os"

// getDeviceID returns 0, false on non-Unix platforms.
// Device ID-based security checks are skipped on these platforms because:
// 1. os.OpenRoot provides primary defense against path traversal
// 2. WalkDir doesn't follow symlinks by default
// 3. Hardlink attacks are primarily a Unix concern
func getDeviceID(info os.FileInfo) (int64, bool) {
	return 0, false
}

// getHardlinkCount returns 0, false on non-Unix platforms.
// Hardlink detection is skipped because Windows handles hard links differently
// and the security implications are different from Unix.
func getHardlinkCount(info os.FileInfo) (uint64, bool) {
	return 0, false
}
