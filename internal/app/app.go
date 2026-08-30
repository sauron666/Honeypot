// Package app wires a MIRAGE deployment together.
//
// It exists so that the assembly -- evidence store, bus, engagement tracker,
// alert dispatcher, decoy farm, API -- is one testable object rather than a
// hundred lines of main(). The end-to-end tests run exactly the same wiring the
// binary does; anything else would be testing a different product.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/alert"
	"github.com/sauron666/Honeypot/internal/api"
	"github.com/sauron666/Honeypot/internal/bus"
	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/drivers/observer"
	"github.com/sauron666/Honeypot/internal/driverset"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/farm"
	"github.com/sauron666/Honeypot/internal/honeyd"
	"github.com/sauron666/Honeypot/internal/presence"
	"github.com/sauron666/Honeypot/internal/store"
	"github.com/sauron666/Honeypot/internal/tokens"
)

// App is an assembled deployment.
type App struct {
	Config     *config.Config
	Store      *store.FileStore
	Bus        *bus.Memory
	Tracker    *engagement.Tracker
	Dispatcher *alert.Dispatcher
	Registry   *drivers.Registry
	Farm       *honeyd.Server
	API        *api.Server
	Tokens     *tokens.Store
	// Presence is the overlay hub, when the deployment declares agents.
	Presence *presence.Hub
	// VMs provisions full-OS decoys, when the deployment declares any.
	VMs *farm.Provisioner
	// Observer watches inside full-OS decoys from the hypervisor, when
	// configured. Sightings are fed through ingest like any other event.
	Observer drivers.ObserverDriver

	log        *slog.Logger
	started    time.Time
	sweepCh    chan struct{}
	observesMu sync.Mutex
	observes   map[string]context.CancelFunc // decoyID → cancel for Observe goroutine
}

// New assembles a deployment from configuration. Nothing binds a port until
// Start is called, so a caller can inspect the assembly first.
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("app: create data dir: %w", err)
	}
	if err := cfg.EnsureSeed(); err != nil {
		return nil, err
	}

	evStore, err := store.OpenFile(cfg.Storage.EvidenceFile, store.FileOptions{
		MemoryWindow: cfg.Storage.MemoryWindow,
		SyncEvery:    cfg.Storage.SyncEvery,
	})
	if err != nil {
		return nil, err
	}
	if n := evStore.RecoveredBytes(); n > 0 {
		// A previous run was killed mid-append. The torn record was dropped and
		// the chain resumed from the last durable event. Saying so plainly
		// matters: silently repairing evidence is exactly what a tamper-evident
		// store must not do without a trace.
		log.Warn("recovered a torn final record from a previous crash; "+
			"the evidence chain resumed from the last durable event",
			"dropped_bytes", n, "file", cfg.Storage.EvidenceFile)
	}

	a := &App{
		Config:  cfg,
		Store:   evStore,
		Bus:     bus.NewMemory(4096, log),
		log:     log,
		started: time.Now(),
		sweepCh: make(chan struct{}),
	}

	a.Tracker = engagement.NewTracker(engagement.Options{
		IdleTimeout: cfg.Engagement.IdleTimeout,
		Emit: func(ctx context.Context, e *event.Event) {
			// Lifecycle events travel the same path as everything else, so they
			// are sealed into the chain like any other evidence. The tracker is
			// not passed back in: it is already mid-update when this fires.
			a.ingest(ctx, e, false)
		},
	})

	minSev, err := config.ParseSeverity(cfg.Alerts.MinSeverity)
	if err != nil {
		return nil, err
	}
	a.Dispatcher = alert.NewDispatcher(alert.Options{
		MinSeverity: minSev, PublicURL: cfg.API.PublicURL, Log: log,
	})

	a.Registry = driverset.Default()
	for _, sc := range cfg.Alerts.Sinks {
		sink, err := a.Registry.Sink(sc.Driver, resolvePaths(sc.Config, cfg.DataDir))
		if err != nil {
			return nil, fmt.Errorf("app: alert sink %q: %w", sc.Driver, err)
		}
		if err := sink.Probe(context.Background()); err != nil {
			// A sink that is unreachable now will be unreachable during an
			// incident, which is the worst time to discover it.
			log.Warn("alert sink is not reachable", "driver", sc.Driver, "err", err)
		}
		a.Dispatcher.AddSink(sink)
	}
	if _, err := a.Bus.Subscribe(bus.SubjectAll, a.Dispatcher.Handle); err != nil {
		return nil, err
	}

	a.Tokens, err = tokens.NewStore(cfg.Tokens.File, cfg.Tokens.BaseURL)
	if err != nil {
		return nil, err
	}
	// Tokens fire two ways: a callback the attacker makes, and the planted
	// value turning up in something they did on a decoy. The watcher covers
	// the second, which is the half nobody else implements.
	watcher := tokens.NewWatcher(a.Tokens, cfg.Tenant, cfg.Site, func(ctx context.Context, e *event.Event) {
		a.ingest(ctx, e, true)
	})
	if _, err := a.Bus.Subscribe(bus.SubjectAll, watcher.Handle); err != nil {
		return nil, err
	}

	hcfg := cfg.HoneydConfig()
	hcfg.DeploySeed = cfg.DeploySeed
	for i := range hcfg.Listeners {
		if hcfg.Listeners[i].Options == nil {
			hcfg.Listeners[i].Options = map[string]any{}
		}
		// Host keys live with the deployment state so they survive restarts; a
		// changing SSH host key is one of the clearest honeypot tells there is.
		if _, ok := hcfg.Listeners[i].Options["host_key_path"]; !ok {
			hcfg.Listeners[i].Options["host_key_path"] = filepath.Join(cfg.DataDir, "hostkeys")
		}
		// The token receiver needs to resolve ids, but honeyd must not know how
		// tokens are stored, so the lookup is injected here.
		if hcfg.Listeners[i].Service == "tokens" {
			hcfg.Listeners[i].Options["lookup"] = honeyd.TokenLookup(a.lookupToken)
		}
	}
	emitter := honeyd.EmitterFunc(func(ctx context.Context, e *event.Event) {
		a.ingest(ctx, e, true)
	})
	a.Farm, err = honeyd.NewServer(hcfg, emitter, a.Tracker, log)
	if err != nil {
		return nil, err
	}

	if len(cfg.VMs.Decoys) > 0 {
		if err := a.buildVMFarm(cfg, log); err != nil {
			return nil, err
		}
	}

	if len(cfg.Presence.Agents) > 0 {
		// The farm serves tunnelled connections exactly as it serves bound
		// ones, so a decoy behind an overlay is not a second kind of decoy.
		a.Presence, err = presence.NewHub(cfg.Presence, a.Farm, log)
		if err != nil {
			return nil, err
		}
	}

	a.API, err = api.New(cfg.API.Listen, api.Deps{
		Store: evStore, Tracker: a.Tracker, Farm: a.Farm, Registry: a.Registry,
		Dispatcher: a.Dispatcher, Tokens: a.Tokens, RunningConfig: cfg,
		Apply:    a.ApplyListeners,
		Presence: a.Presence,
		VMs:      a.VMs,
		Observer: a.Observer,
		Tenant:   cfg.Tenant, Site: cfg.Site,
		StartedAt: a.started, Log: log, Token: cfg.API.Token,
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// buildVMFarm opens the compute and fabric drivers and assembles the
// provisioner. It is separate from New because it is the one part of assembly
// that talks to a hypervisor, and a deployment with no full-OS decoys must not
// pay for a driver it never uses.
func (a *App) buildVMFarm(cfg *config.Config, log *slog.Logger) error {
	name := cfg.Drivers.Compute
	if name == "" {
		name = "inproc"
	}
	computeInfo, ok := a.Registry.Info(drivers.KindCompute, name)
	if !ok {
		return fmt.Errorf("app: unknown compute driver %q", name)
	}
	compute, err := a.Registry.Compute(name, resolvePaths(cfg.Drivers.ComputeConfig, cfg.DataDir))
	if err != nil {
		return fmt.Errorf("app: compute driver %q: %w", name, err)
	}
	if err := compute.Probe(context.Background()); err != nil {
		// Unlike a sink, this one is fatal: there is nowhere to put the decoys.
		return fmt.Errorf("app: compute driver %q is not usable: %w", name, err)
	}

	var fab drivers.FabricDriver
	if cfg.Drivers.Fabric != "" {
		fab, err = a.Registry.Fabric(cfg.Drivers.Fabric, cfg.Drivers.FabricConfig)
		if err != nil {
			return fmt.Errorf("app: fabric driver %q: %w", cfg.Drivers.Fabric, err)
		}
		if err := fab.Probe(context.Background()); err != nil {
			return fmt.Errorf("app: fabric driver %q is not usable: %w", cfg.Drivers.Fabric, err)
		}
		if err := fab.EnsureZones(context.Background(), []drivers.Zone{
			drivers.ZoneDirty, drivers.ZoneMgmt}); err != nil {
			log.Warn("app: could not install the containment zones; "+
				"the assertion below will say whether that matters", "err", err)
		}
	}

	a.VMs, err = farm.New(farm.Options{
		Compute: compute, ComputeInfo: computeInfo, Fabric: fab,
		ContainmentUnenforced: cfg.VMs.Containment == "unenforced",
		Publish: func(e *event.Event) {
			a.ingest(context.Background(), e, true)
		},
		Log: log,
	})
	if err != nil {
		return err
	}
	for _, d := range cfg.VMs.Decoys {
		if d.Revert == farm.RevertOnEngagementEnd && !a.VMs.CanRevert() {
			log.Warn("a full-OS decoy asks to be reset after each engagement, but this compute "+
				"driver cannot snapshot; it will stay as the attacker left it",
				"decoy", d.ID, "driver", name)
		}
	}

	if cfg.Drivers.Observer != "" {
		if err := a.buildObserver(cfg, compute, log); err != nil {
			return err
		}
	}
	return nil
}

// buildObserver opens the observer driver and wires the decoy→domain resolver
// from the compute driver. The resolver is how the observer knows which Xen
// domain to attach to when given a MIRAGE decoy id.
func (a *App) buildObserver(cfg *config.Config, compute drivers.ComputeDriver, log *slog.Logger) error {
	obs, err := a.Registry.Observer(cfg.Drivers.Observer, cfg.Drivers.ObserverConfig)
	if err != nil {
		return fmt.Errorf("app: observer driver %q: %w", cfg.Drivers.Observer, err)
	}
	if err := obs.Probe(context.Background()); err != nil {
		log.Warn("observer driver is not usable on this host; "+
			"VM decoys will run without inside-the-guest observation",
			"driver", cfg.Drivers.Observer, "err", err)
		return nil
	}
	// Wire the domain resolver for DRAKVUF: decoy id → (Xen domain, profile).
	if d, ok := obs.(*observer.Drakvuf); ok {
		d.SetDomainResolver(func(decoyID string) (string, string, error) {
			st, err := compute.Status(context.Background(), decoyID)
			if err != nil {
				return "", "", fmt.Errorf("observer: cannot resolve decoy %q to a domain: %w", decoyID, err)
			}
			return st.Handle, "", nil
		})
	}
	a.Observer = obs
	a.observes = make(map[string]context.CancelFunc)
	log.Info("observer driver ready", "driver", cfg.Drivers.Observer,
		"capabilities", obs.Info().Capabilities)
	return nil
}

// startObserving launches an Observe stream for a VM decoy. Each sighting is
// converted to an OCSF event and fed through ingest, so it joins the evidence
// chain and the engagement tracker like any emulated-service event.
func (a *App) startObserving(decoyID, persona string) {
	if a.Observer == nil {
		return
	}
	a.observesMu.Lock()
	if _, running := a.observes[decoyID]; running {
		a.observesMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.observes[decoyID] = cancel
	a.observesMu.Unlock()

	ch, err := a.Observer.Observe(ctx, decoyID)
	if err != nil {
		cancel()
		if !errors.Is(err, drivers.ErrObserveUnsupported) {
			a.log.Warn("could not attach observer to VM decoy",
				"decoy", decoyID, "err", err)
		}
		a.observesMu.Lock()
		delete(a.observes, decoyID)
		a.observesMu.Unlock()
		return
	}
	a.log.Info("observing inside VM decoy", "decoy", decoyID)
	go func() {
		defer func() {
			a.observesMu.Lock()
			delete(a.observes, decoyID)
			a.observesMu.Unlock()
		}()
		for s := range ch {
			e := observer.SightingToEvent(s, a.Config.Tenant, a.Config.Site, persona)
			a.ingest(ctx, e, true)
		}
	}()
}

// stopObserving cancels the Observe stream for a decoy.
func (a *App) stopObserving(decoyID string) {
	a.observesMu.Lock()
	cancel, ok := a.observes[decoyID]
	a.observesMu.Unlock()
	if ok {
		cancel()
		a.log.Info("stopped observing VM decoy", "decoy", decoyID)
	}
}

// stopAllObservers cancels every running Observe stream.
func (a *App) stopAllObservers() {
	a.observesMu.Lock()
	for id, cancel := range a.observes {
		cancel()
		delete(a.observes, id)
	}
	a.observesMu.Unlock()
}

// ApplyListeners reconciles the running farm with a new listener set.
//
// It exists rather than the API calling the farm directly because the runtime
// options a listener needs -- where SSH host keys live, how the token receiver
// resolves ids -- are injected here. Applying a manifest without them would
// produce decoys with fresh host keys on every apply, and a token receiver that
// cannot look anything up.
func (a *App) ApplyListeners(listeners []honeyd.ListenerConfig) (added, removed []string, err error) {
	return a.Farm.Reconcile(a.withRuntimeOptions(listeners))
}

// withRuntimeOptions fills in the options the process supplies, leaving what
// the manifest set intact.
func (a *App) withRuntimeOptions(listeners []honeyd.ListenerConfig) []honeyd.ListenerConfig {
	out := make([]honeyd.ListenerConfig, len(listeners))
	copy(out, listeners)
	for i := range out {
		opts := map[string]any{}
		for k, v := range out[i].Options {
			opts[k] = v
		}
		// Host keys live with the deployment state so they survive restarts; a
		// changing SSH host key is one of the clearest honeypot tells there is.
		if _, ok := opts["host_key_path"]; !ok {
			opts["host_key_path"] = filepath.Join(a.Config.DataDir, "hostkeys")
		}
		if out[i].Service == "tokens" {
			opts["lookup"] = honeyd.TokenLookup(a.lookupToken)
		}
		out[i].Options = opts
	}
	return out
}

// lookupToken resolves and fires a honeytoken by id.
func (a *App) lookupToken(id string) (label, kind, location string, ok bool) {
	t, ok := a.Tokens.Fire(id)
	if !ok {
		return "", "", "", false
	}
	return t.Label, string(t.Type), t.Location, true
}

// ingest is the single path every event takes: sealed into the evidence chain
// first, then folded into its engagement, then published. Persisting before
// publishing means no subscriber can act on evidence that is not yet durable.
func (a *App) ingest(ctx context.Context, e *event.Event, track bool) {
	if err := a.Store.Append(ctx, e); err != nil {
		// Losing evidence is the one failure worth shouting about, and there is
		// nothing to fall back to. Keep serving anyway: a decoy that stops
		// answering is more damaging than one that logs to stderr.
		a.log.Error("failed to persist event", "err", err, "event_uid", e.Metadata.UID)
		return
	}
	if track {
		a.Tracker.Observe(e)
	}
	if err := a.Bus.Publish(ctx, e); err != nil && !errors.Is(err, bus.ErrClosed) {
		a.log.Warn("failed to publish event", "err", err, "event_uid", e.Metadata.UID)
	}
}

// Start binds the decoys and the API.
func (a *App) Start(ctx context.Context) error {
	if err := a.Farm.Start(ctx); err != nil {
		return err
	}
	if a.VMs != nil {
		changes, err := a.VMs.Reconcile(ctx, a.Config.VMs.Decoys)
		if err != nil {
			a.Farm.Close()
			return err
		}
		for _, c := range changes {
			a.log.Info("full-OS decoy", "id", c.ID, "action", c.Action, "reason", c.Reason)
		}
		// Attach the observer to every running VM decoy.
		if a.Observer != nil {
			personaOf := map[string]string{}
			for _, d := range a.Config.VMs.Decoys {
				personaOf[d.ID] = d.Persona
			}
			for _, st := range a.VMs.Status() {
				if st.State == string(drivers.StateRunning) {
					a.startObserving(st.ID, personaOf[st.ID])
				}
			}
		}
	}
	if a.Presence != nil {
		if err := a.Presence.Start(ctx); err != nil {
			a.Farm.Close()
			return err
		}
	}
	if err := a.API.Start(); err != nil {
		a.Farm.Close()
		if a.Presence != nil {
			a.Presence.Close()
		}
		return err
	}
	go a.sweepLoop(ctx)
	return nil
}

// sweepLoop closes engagements that have gone quiet, which is what turns a live
// interaction into a finished report.
func (a *App) sweepLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.sweepCh:
			return
		case <-t.C:
			closed := a.Tracker.SweepClosed()
			if len(closed) == 0 {
				continue
			}
			a.log.Info("engagements closed after going quiet", "count", len(closed))
			if a.VMs == nil {
				continue
			}
			// Now, and not before: the attacker has gone quiet, so resetting a
			// decoy they were in is invisible to them rather than a tell.
			for _, e := range closed {
				a.VMs.OnEngagementClosed(ctx, e.Decoys)
			}
		}
	}
}

// Stop shuts everything down in dependency order and flushes the evidence file.
func (a *App) Stop(ctx context.Context) error {
	close(a.sweepCh)
	a.stopAllObservers()
	if err := a.API.Shutdown(ctx); err != nil {
		a.log.Warn("api shutdown", "err", err)
	}
	if a.Presence != nil {
		a.Presence.Close()
	}
	a.Farm.Close()
	if a.Observer != nil {
		a.Observer.Close()
	}
	a.Tracker.Sweep()
	a.Bus.Close()
	a.Registry.Close()
	return a.Store.Close()
}

// resolvePaths makes relative sink paths relative to the data directory, so a
// configuration file does not depend on the working directory it is run from.
func resolvePaths(cfg map[string]any, dataDir string) map[string]any {
	if cfg == nil {
		return nil
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	if p, ok := out["path"].(string); ok && !filepath.IsAbs(p) {
		out["path"] = filepath.Join(dataDir, p)
	}
	return out
}
