// Command mirage-presence is the Presence Agent: it makes decoys appear in a
// network segment without anything being deployed into it.
//
// It claims unused addresses in the segment it runs in and tunnels whatever
// arrives to the MIRAGE hub, where the real decoys live. Nothing about the
// segment changes: no VLANs, no firewall rules, no switch configuration. That
// is the point -- deception projects usually die in the network change request,
// not in the technology.
//
// The agent forwards bytes and nothing else. It never interprets or executes
// anything a decoy sends, and it holds no credential beyond its own token.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/sauron666/Honeypot/internal/presence"
	"github.com/sauron666/Honeypot/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mirage-presence: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		cfgPath   = flag.String("config", "", "path to an agent configuration file")
		hub       = flag.String("hub", "", "hub address, host:port")
		token     = flag.String("token", "", "shared token (prefer MIRAGE_PRESENCE_TOKEN)")
		id        = flag.String("id", "", "agent id, as declared on the hub")
		addresses = flag.String("addresses", "", "comma-separated addresses to claim")
		services  = flag.String("services", "", "comma-separated service:port pairs, e.g. ssh:22,http:80")
		tlsCert   = flag.String("tls-cert", "", "this agent's certificate (from miragectl presence-ca)")
		tlsKey    = flag.String("tls-key", "", "this agent's private key")
		tlsCA     = flag.String("tls-ca", "", "CA that signed the hub's certificate")
		tlsName   = flag.String("tls-server-name", "",
			"name to expect on the hub certificate (default: the host in -hub)")
		logLevel = flag.String("log-level", "info", "debug, info, warn or error")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version.String() + " (presence agent)")
		return nil
	}

	var set presence.AgentSettings
	if *cfgPath != "" {
		raw, err := os.ReadFile(*cfgPath)
		if err != nil {
			return err
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&set); err != nil {
			return fmt.Errorf("parse %s: %w", *cfgPath, err)
		}
	}

	// Flags override the file, and the environment overrides both for the
	// token: a secret on a command line is visible in every process listing.
	if *hub != "" {
		set.Hub = *hub
	}
	if *id != "" {
		set.ID = *id
	}
	if *token != "" {
		set.Token = *token
	}
	if env := os.Getenv("MIRAGE_PRESENCE_TOKEN"); env != "" {
		set.Token = env
	}
	if *tlsCert != "" {
		set.TLS.CertFile = *tlsCert
	}
	if *tlsKey != "" {
		set.TLS.KeyFile = *tlsKey
	}
	if *tlsCA != "" {
		set.TLS.CAFile = *tlsCA
	}
	if *tlsName != "" {
		set.TLS.ServerName = *tlsName
	}
	if *addresses != "" {
		set.Addresses = splitList(*addresses)
	}
	if *services != "" {
		parsed, err := parseServices(*services)
		if err != nil {
			return err
		}
		set.Services = parsed
	}

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	agent, err := presence.NewAgent(set, log)
	if err != nil {
		return err
	}

	if !set.TLS.Enabled() {
		// The tunnel carries the token and everything an attacker says to the
		// decoy. Without TLS both are readable by anyone on the path between
		// this segment and the hub.
		log.Warn("presence agent has no TLS configured; " +
			"run it only inside an existing VPN, or issue material with 'miragectl presence-ca'")
	}

	log.Info("starting presence agent",
		"version", version.Version, "hub", set.Hub, "id", set.ID,
		"addresses", len(set.Addresses), "services", len(set.Services),
		"tls", set.TLS.Enabled())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agent.Run(ctx); err != nil {
		return err
	}
	log.Info("presence agent stopped")
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

// parseServices reads "ssh:22,http:80".
func parseServices(s string) ([]presence.ServiceBinding, error) {
	var out []presence.ServiceBinding
	for _, part := range splitList(s) {
		name, portStr, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("service %q must be written as name:port", part)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("service %q has a bad port: %w", part, err)
		}
		out = append(out, presence.ServiceBinding{Service: strings.TrimSpace(name), Port: port})
	}
	return out, nil
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
