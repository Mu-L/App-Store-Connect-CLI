//go:build !windows

package rootfs

func unsupportedDirectorySyncError(error) bool {
	// Directory fsync failures remain actionable on platforms where the
	// operation is supported; do not weaken durability guarantees.
	return false
}
