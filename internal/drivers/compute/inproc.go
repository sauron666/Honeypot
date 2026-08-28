package compute

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// InprocInfo describes the built-in driver used by profile P0.
func InprocInfo() drivers.Info {
	return drivers.Info{
		Name: "inproc",
		Kind: drivers.KindCompute,
		Summary: "Decoys served by the MIRAGE process itself: no hypervisor, no containers. " +
			"This is what makes 'honeypot in a box' a ten-minute install.",
		Capabilities: []drivers.Capability{},
	}
}

// Inproc is a bookkeeping-only compute driver. The decoys it "runs" are the
// emulated services inside this process, so there is nothing to clone or
// snapshot; it exists so that the rest of the system has one uniform way to
// enumerate decoys regardless of where they live.
type Inproc struct {
	mu     sync.RWMutex
	decoys map[string]drivers.DecoyStatus
}

// NewInproc builds the driver.
func NewInproc(map[string]any) (drivers.Driver, error) {
	return &Inproc{decoys: map[string]drivers.DecoyStatus{}}, nil
}

func (i *Inproc) Info() drivers.Info          { return InprocInfo() }
func (i *Inproc) Probe(context.Context) error { return nil }
func (i *Inproc) Close() error                { return nil }

func (i *Inproc) Create(_ context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	st := drivers.DecoyStatus{
		ID: spec.ID, Handle: "inproc/" + spec.ID,
		State: drivers.StateRunning, CreatedAt: time.Now(),
	}
	i.decoys[spec.ID] = st
	return st, nil
}

func (i *Inproc) setState(id string, s drivers.DecoyState) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	st, ok := i.decoys[id]
	if !ok {
		return fmt.Errorf("compute/inproc: unknown decoy %s", id)
	}
	st.State = s
	i.decoys[id] = st
	return nil
}

func (i *Inproc) Start(_ context.Context, id string) error {
	return i.setState(id, drivers.StateRunning)
}

func (i *Inproc) Stop(_ context.Context, id string) error {
	return i.setState(id, drivers.StateStopped)
}

func (i *Inproc) Destroy(_ context.Context, id string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.decoys, id)
	return nil
}

func (i *Inproc) Status(_ context.Context, id string) (drivers.DecoyStatus, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	st, ok := i.decoys[id]
	if !ok {
		return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
	}
	return st, nil
}

func (i *Inproc) List(context.Context) ([]drivers.DecoyStatus, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]drivers.DecoyStatus, 0, len(i.decoys))
	for _, st := range i.decoys {
		out = append(out, st)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func (i *Inproc) Snapshot(context.Context, string, string) error {
	return fmt.Errorf("%w: in-process decoys hold no persistent state", ErrNotSupported)
}

func (i *Inproc) Revert(context.Context, string, string) error {
	return fmt.Errorf("%w: in-process decoys hold no persistent state", ErrNotSupported)
}

var _ drivers.ComputeDriver = (*Inproc)(nil)
