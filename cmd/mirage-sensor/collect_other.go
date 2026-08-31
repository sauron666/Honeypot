//go:build !linux && !windows

package main

import (
	"context"
	"fmt"
	"runtime"
)

// The in-guest sensor's collectors are Linux (netlink process connector) and
// Windows (Sysmon) only. On any other platform it builds but refuses to run,
// honestly, rather than pretending to observe.
func collect(ctx context.Context, decoyID string, fwd *forwarder) error {
	return fmt.Errorf("mirage-sensor: no collector for %s; supported guests are Linux and Windows", runtime.GOOS)
}
