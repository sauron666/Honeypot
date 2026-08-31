package app

import (
	"context"
	"log/slog"

	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/fusetrap"
	"github.com/sauron666/Honeypot/internal/ransomware"
)

// buildTrap constructs the ransomware trap and wires its findings into the same
// ingest path every other event takes, and its confirmation into a snapshot of
// the crime scene. It does not mount anything yet -- startTrap does that once
// the rest of the deployment is up.
func (a *App) buildTrap(cfg *config.Config, log *slog.Logger) {
	shareID := cfg.Trap.ShareID
	if shareID == "" {
		shareID = "fileserver"
	}
	a.Trap = fusetrap.New(fusetrap.Options{
		ShareID: shareID,
		OnEvent: func(ev fusetrap.Event) {
			// Persist and publish on a background context: the FUSE thread that
			// produced this is the attacker's own, and must not be held on the
			// evidence store.
			a.ingest(context.Background(), trapFindingEvent(cfg, shareID, ev), true)
		},
		OnConfirmed: func(v ransomware.Verdict, m fusetrap.Metrics) {
			a.onRansomwareConfirmed(cfg, shareID, v, m)
		},
	})
	log.Info("ransomware trap armed", "share", shareID,
		"mountpoint", cfg.Trap.Mountpoint, "snapshot_decoy", cfg.Trap.SnapshotDecoy)
}

// startTrap mounts the trap share. A failure is logged, never fatal: the trap
// is a defence-in-depth layer, and a director that refuses to start because a
// mountpoint is busy is worse than one running without the trap.
func (a *App) startTrap() {
	if a.Trap == nil {
		return
	}
	mp := a.Config.Trap.Mountpoint
	if mp == "" {
		a.log.Warn("ransomware trap has no mountpoint configured; not mounting")
		return
	}
	m, err := fusetrap.Mount(mp, a.Trap, false)
	if err != nil {
		a.log.Warn("ransomware trap could not be mounted; "+
			"the detector still works through the emulated SMB/FTP share",
			"mountpoint", mp, "err", err)
		return
	}
	a.trapMount = m
	a.log.Info("ransomware trap mounted", "mountpoint", mp)
}

// stopTrap unmounts the trap share.
func (a *App) stopTrap() {
	if a.trapMount != nil {
		if err := a.trapMount.Close(); err != nil {
			a.log.Warn("could not unmount the ransomware trap", "err", err)
		}
		a.trapMount = nil
	}
}

// onRansomwareConfirmed preserves the crime scene: it snapshots the configured
// decoy (so the encrypted state is captured on the hypervisor for forensics)
// and records a critical, ATT&CK-tagged event carrying the measured impact.
func (a *App) onRansomwareConfirmed(cfg *config.Config, shareID string, v ransomware.Verdict, m fusetrap.Metrics) {
	if cfg.Trap.SnapshotDecoy != "" && a.compute != nil {
		name := "ransomware-" + v.LastSeen.UTC().Format("20060102T150405Z")
		if err := a.compute.Snapshot(context.Background(), cfg.Trap.SnapshotDecoy, name); err != nil {
			a.log.Warn("could not snapshot the decoy on ransomware confirmation",
				"decoy", cfg.Trap.SnapshotDecoy, "err", err)
		} else {
			a.log.Info("snapshotted the crime scene on ransomware confirmation",
				"decoy", cfg.Trap.SnapshotDecoy, "snapshot", name)
		}
	}

	e := event.New(event.ClassProcessActivity, 1, event.SeverityCritical, event.PlaneObserver).
		WithMessage("ransomware confirmed on trap share %q: %d files touched, sure after %d operations",
			shareID, v.FilesTouched, m.ConfirmOps).
		WithAttack(event.Technique{Tactic: "TA0040", Technique: "T1486", Name: "Data Encrypted for Impact"})
	e.Mirage.TenantID, e.Mirage.SiteID = cfg.Tenant, cfg.Site
	e.Set("share", shareID)
	e.Set("files_touched", v.FilesTouched)
	e.Set("confirm_ops", m.ConfirmOps)
	e.Set("first_signal_ops", m.FirstSignalOps)
	e.Set("score", v.Score)
	if len(v.Extensions) > 0 {
		e.Set("extensions", v.Extensions)
	}
	a.ingest(context.Background(), e, true)
}

// trapFindingEvent turns a single trap finding into an OCSF event. The severity
// tracks the detector's own signal weighting; the confirmation is upgraded to
// critical and carries the T1486 technique, mirroring the DRAKVUF crypto hook.
func trapFindingEvent(cfg *config.Config, shareID string, ev fusetrap.Event) *event.Event {
	sev := event.SeverityMedium
	class := event.ClassFileActivity
	msg := "ransomware signal on trap share " + shareID + ": " + string(ev.Finding.Kind)
	if ev.Finding.Message != "" {
		msg = "trap share " + shareID + ": " + ev.Finding.Message
	}
	switch ev.Finding.Kind {
	case ransomware.SignalCanary:
		sev = event.SeverityHigh
	case ransomware.SignalConfirmed:
		sev = event.SeverityCritical
	}

	e := event.New(class, 1, sev, event.PlaneObserver).WithMessage("%s", msg)
	e.Mirage.TenantID, e.Mirage.SiteID = cfg.Tenant, cfg.Site
	e.Set("share", shareID)
	e.Set("signal", string(ev.Finding.Kind))
	if ev.Finding.Path != "" {
		e.Set("path", ev.Finding.Path)
	}
	if ev.Finding.Kind == ransomware.SignalConfirmed {
		e.WithAttack(event.Technique{Tactic: "TA0040", Technique: "T1486", Name: "Data Encrypted for Impact"})
	}
	return e
}
