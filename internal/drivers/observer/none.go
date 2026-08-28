package observer

import (
	"context"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// NoneInfo describes the observer for deployments with no hypervisor.
func NoneInfo() drivers.Info {
	return drivers.Info{
		Name: "none",
		Kind: drivers.KindObserver,
		Summary: "No inside-the-decoy observation. The emulated services and the evidence chain " +
			"still record everything they see; this driver simply declares, honestly, that " +
			"nothing watches inside a full-OS decoy here.",
		Capabilities: nil,
	}
}

// None is the null observer. It exists so that a deployment without VMI has a
// valid, declared choice rather than a missing capability, and so the observer
// category is exercised by more than one implementation (ADR-008). It claims no
// capabilities, so the planner and UI correctly show that deep observation is
// unavailable rather than pretending otherwise.
type None struct{}

// NewNone builds the null observer.
func NewNone(map[string]any) (drivers.Driver, error) { return &None{}, nil }

func (None) Info() drivers.Info          { return NoneInfo() }
func (None) Probe(context.Context) error { return nil }
func (None) Close() error                { return nil }

func (None) Attach(context.Context, string) error { return nil }
func (None) Detach(context.Context, string) error { return nil }
func (None) DumpMemory(context.Context, string, string) error {
	return drivers.ErrObserveUnsupported
}

// Observe returns the unsupported error rather than an empty stream, so a caller
// that needs sightings learns plainly that it will get none here.
func (None) Observe(context.Context, string) (<-chan drivers.Sighting, error) {
	return nil, drivers.ErrObserveUnsupported
}

var _ drivers.ObserverDriver = (*None)(nil)
