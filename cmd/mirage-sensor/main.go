package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var verbose bool

func logf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

func main() {
	director := flag.String("director", "", "director agent endpoint, e.g. https://mirage:8423 (required)")
	token := flag.String("token", "", "shared token the director's agent observer expects (required)")
	decoyID := flag.String("decoy-id", "", "the decoy id this guest represents, as MIRAGE knows it (required)")
	interval := flag.Duration("interval", 2*time.Second, "how often to flush batched events")
	flag.BoolVar(&verbose, "verbose", false, "log activity to stderr")
	flag.Parse()

	if *director == "" || *token == "" || *decoyID == "" {
		fmt.Fprintln(os.Stderr, "mirage-sensor: --director, --token and --decoy-id are required")
		fmt.Fprintln(os.Stderr, "\nThe in-guest sensor for full-OS decoys. It forwards process")
		fmt.Fprintln(os.Stderr, "execution to the director's agent observer, so every command an")
		fmt.Fprintln(os.Stderr, "attacker runs reaches the evidence chain on any hypervisor.")
		os.Exit(2)
	}

	fwd := newForwarder(*director, *token)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go fwd.run(ctx, *interval)

	logf("mirage-sensor watching decoy %q, forwarding to %s", *decoyID, *director)
	if err := collect(ctx, *decoyID, fwd); err != nil {
		fmt.Fprintf(os.Stderr, "mirage-sensor: %v\n", err)
		os.Exit(1)
	}
}
