// Package compute holds ComputeDriver implementations: where decoys actually
// run. Two drivers ship from day one (ADR-008): podman for the container farm
// and libvirt for full-OS decoys with introspection.
package compute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ErrNotSupported is returned by operations the backend cannot perform. Callers
// should check the driver's declared capabilities first; this is the backstop.
var ErrNotSupported = errors.New("compute: operation not supported by this driver")

// runner executes an external CLI. It exists so that drivers built on shelling
// out (podman, virsh, pvesh) share timeout, context and error handling, and so
// tests can substitute a fake.
type runner interface {
	run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

type execRunner struct {
	timeout time.Duration
}

func (r execRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s %s: timed out after %s", name, args[0], timeout)
		}
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return out.String(), nil
}

// binaryExists reports whether a CLI is on PATH, for Probe.
func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
