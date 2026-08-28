package nac

import (
	"context"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// NoneInfo describes the NAC driver for deployments with no network access
// control to steer through.
func NoneInfo() drivers.Info {
	return drivers.Info{
		Name: "none",
		Kind: drivers.KindNAC,
		Summary: "No network access control. Unknown devices are not steered anywhere; the decoys " +
			"still catch whatever reaches them. This is the honest choice when there is no RADIUS " +
			"or 802.1X fabric to reassign a port through.",
		Capabilities: nil,
	}
}

// None is the null NAC driver. It exists so that a deployment without a RADIUS
// or 802.1X fabric has a valid, declared choice rather than a missing category,
// and so the NAC abstraction is exercised by more than one implementation
// (ADR-008): an abstraction with a single implementation is not an abstraction.
type None struct{}

// NewNone builds the null NAC driver.
func NewNone(map[string]any) (drivers.Driver, error) { return &None{}, nil }

func (None) Info() drivers.Info          { return NoneInfo() }
func (None) Probe(context.Context) error { return nil }
func (None) Close() error                { return nil }

// SteerToDeception is a no-op that reports it did nothing, so a caller relying
// on steering learns plainly that none happens here rather than believing a
// device was redirected when it was not.
func (None) SteerToDeception(context.Context, string, string, int) error {
	return drivers.ErrNoOp
}
