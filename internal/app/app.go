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
	"time"

	"github.com/sauron666/Honeypot/internal/alert"
	"github.com/sauron666/Honeypot/internal/api"
	"github.com/sauron666/Honeypot/internal/bus"
	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/driverset"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/honeyd"
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

	log     *slog.Logger
	started time.Time
	sweepCh chan struct{}
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

	a.API, err = api.New(cfg.API.Listen, api.Deps{
		Store: evStore, Tracker: a.Tracker, Farm: a.Farm, Registry: a.Registry,
		Dispatcher: a.Dispatcher, Tokens: a.Tokens, RunningConfig: cfg,
		Apply:  a.ApplyListeners,
		Tenant: cfg.Tenant, Site: cfg.Site,
		StartedAt: a.started, Log: log, Token: cfg.API.Token,
	})
	if err != nil {
		return nil, err
	}
	return a, nil
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
	if err := a.API.Start(); err != nil {
		a.Farm.Close()
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
			if n := a.Tracker.Sweep(); n > 0 {
				a.log.Info("engagements closed after going quiet", "count", n)
			}
		}
	}
}

// Stop shuts everything down in dependency order and flushes the evidence file.
func (a *App) Stop(ctx context.Context) error {
	close(a.sweepCh)
	if err := a.API.Shutdown(ctx); err != nil {
		a.log.Warn("api shutdown", "err", err)
	}
	a.Farm.Close()
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
