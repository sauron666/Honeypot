// Command mirage-director is the MIRAGE control plane.
//
// In profile P0 ("honeypot in a box") this single binary is the whole product:
// it runs the decoys, seals their evidence into a tamper-evident chain, stitches
// interactions into engagements, raises alerts and serves the operator console.
// Larger profiles move the decoys onto hypervisors behind the compute driver and
// keep this process as the control plane.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sauron666/Honeypot/internal/app"
	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mirage-director: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		cfgPath   = flag.String("config", "profiles/p0-box.yaml", "path to the configuration file")
		checkOnly = flag.Bool("check", false, "validate the configuration and exit")
		showVer   = flag.Bool("version", false, "print version and exit")
		logLevel  = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version.String())
		return nil
	}

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *checkOnly {
		fmt.Printf("configuration %s is valid: %d decoys, %d listeners\n",
			*cfgPath, len(cfg.Honeyd.Decoys), len(cfg.Listeners()))
		for _, w := range cfg.Warnings() {
			fmt.Printf("warning: %s\n", w)
		}
		return nil
	}
	for _, w := range cfg.Warnings() {
		log.Warn(w)
	}

	a, err := app.New(cfg, log)
	if err != nil {
		return err
	}
	if st := a.Store.Stats(); st.Events > 0 {
		log.Info("resumed evidence chain", "events", st.Events, "head_seq", st.HeadSeq)
	}
	log.Info("starting", "version", version.Version, "tenant", cfg.Tenant, "site", cfg.Site,
		"decoys", len(cfg.Honeyd.Decoys), "listeners", len(cfg.Listeners()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.Start(ctx); err != nil {
		return err
	}
	log.Info("operator console ready", "url", "http://"+cfg.API.Listen)

	<-ctx.Done()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.Stop(shutdownCtx); err != nil {
		return err
	}
	log.Info("stopped cleanly")
	return nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}
