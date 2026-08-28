// Package fabric holds FabricDriver implementations: what keeps the decoy
// segment from becoming a route into the estate it is meant to protect.
//
// Two drivers ship, and they answer different questions on purpose (ADR-008).
// nftables reads and writes the intent -- the rules that are supposed to hold.
// probe tests the reality -- what a packet leaving a decoy actually reaches.
// A deployment where those two disagree is exactly the deployment that turns a
// honeypot into a beachhead, and only running both finds it.
package fabric

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ErrNotSupported is returned by operations a backend cannot perform.
var ErrNotSupported = errors.New("fabric: operation not supported by this driver")

// runner executes an external CLI, so that tests can substitute a fake instead
// of requiring root and a live packet filter.
type runner interface {
	run(ctx context.Context, name string, args ...string) (string, error)
	// runInput feeds stdin, which is how a whole nftables ruleset is applied
	// as one transaction: a ruleset applied rule by rule leaves the decoy
	// segment half-open for as long as it takes to finish.
	runInput(ctx context.Context, stdin string, name string, args ...string) (string, error)
}

type execRunner struct{ timeout time.Duration }

func (r execRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	return r.runInput(ctx, "", name, args...)
}

func (r execRunner) runInput(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s: timed out after %s", name, timeout)
		}
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return out.String(), nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// stringsFrom reads a config value that may be a single string or a list, which
// is what people actually write in YAML.
func stringsFrom(cfg map[string]any, key string) []string {
	switch v := cfg[key].(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		return splitList(v)
	case []string:
		return v
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stringFrom(cfg map[string]any, key, def string) string {
	if v, ok := cfg[key].(string); ok && v != "" {
		return v
	}
	return def
}
