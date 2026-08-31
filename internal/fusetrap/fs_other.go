//go:build !linux

package fusetrap

import "errors"

// ErrUnsupported is returned when a FUSE mount is attempted off Linux. The
// portable Trap still works everywhere (and is fully tested); only the kernel
// mount is Linux-only. A deployment on another OS drives the trap through the
// emulated SMB share instead of a real FUSE mount.
var ErrUnsupported = errors.New("fusetrap: FUSE mount is only supported on Linux")

// Mounted is a stub so callers compile on every platform.
type Mounted struct{}

// Wait returns immediately on unsupported platforms.
func (m *Mounted) Wait() {}

// Close is a no-op on unsupported platforms.
func (m *Mounted) Close() error { return nil }

// Mount reports that FUSE mounting is unavailable on this platform.
func Mount(mountpoint string, t *Trap, debug bool) (*Mounted, error) {
	return nil, ErrUnsupported
}
