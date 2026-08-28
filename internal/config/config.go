// Package config loads and validates MIRAGE's declarative configuration.
//
// The file is the deployment: it names the decoys, their personas, the services
// they answer, where alerts go and which drivers back everything. This is the
// first half of Deception-as-Code (docs/11-IDEAS.md §1) -- the same document
// applies whether the decoys run in this process, on Podman or on a hypervisor.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/honeyd"
)

// Config is a complete MIRAGE deployment.
type Config struct {
	// Tenant and Site identify this deployment in every event it produces.
	Tenant string `yaml:"tenant"`
	Site   string `yaml:"site"`

	// DeploySeed makes generated decoy content stable across restarts while
	// differing between installations. Leave it empty and one is generated and
	// written to the data directory on first start.
	DeploySeed string `yaml:"deploy_seed"`

	DataDir string `yaml:"data_dir"`
	Profile string `yaml:"profile"`

	API        APIConfig        `yaml:"api"`
	Honeyd     HoneydConfig     `yaml:"honeyd"`
	Engagement EngagementConfig `yaml:"engagement"`
	Alerts     AlertConfig      `yaml:"alerts"`
	Storage    StorageConfig    `yaml:"storage"`
	Drivers    DriverConfig     `yaml:"drivers"`
	Tokens     TokenConfig      `yaml:"tokens"`
}

// TokenConfig configures honeytoken minting.
type TokenConfig struct {
	// BaseURL is the address an attacker can reach, and is what minted callback
	// URLs point at. It must be reachable from wherever the token will be
	// planted -- which is emphatically not the management address.
	BaseURL string `yaml:"base_url"`
	File    string `yaml:"file"`
}

// APIConfig configures the management API and UI.
type APIConfig struct {
	// Listen defaults to loopback. Binding the management interface to a
	// routable address by accident is how a deception platform becomes the
	// most interesting target on the network.
	Listen string `yaml:"listen"`
	// Token, when set, is required as a Bearer token on every API request.
	Token string `yaml:"token"`
	// PublicURL is used to build the links carried on alerts.
	PublicURL string `yaml:"public_url"`
}

// HoneydConfig configures the emulated service farm.
type HoneydConfig struct {
	Bind               string        `yaml:"bind"`
	Decoys             []DecoyConfig `yaml:"decoys"`
	MaxSessionDuration time.Duration `yaml:"max_session_duration"`
	IdleTimeout        time.Duration `yaml:"idle_timeout"`
	MaxTranscriptBytes int           `yaml:"max_transcript_bytes"`
	MaxConnsPerIP      int           `yaml:"max_conns_per_ip"`
	MaxConnsTotal      int           `yaml:"max_conns_total"`
}

// DecoyConfig is one decoy: an identity, the addresses it occupies and the
// ports it answers.
type DecoyConfig struct {
	ID      string `yaml:"id"`
	Persona string `yaml:"persona"`
	// Addresses are the IPs this decoy answers on. Empty means the farm's bind
	// address. Listing several is projection: one process presenting the same
	// decoy on every unused address in a subnet, which is how a handful of
	// decoys cover a whole segment. The addresses must exist on the host --
	// see profiles/README.md for adding them.
	Addresses []string        `yaml:"addresses"`
	Services  []ServiceConfig `yaml:"services"`
}

// ServiceConfig is one listening port on a decoy.
type ServiceConfig struct {
	Service string         `yaml:"service"`
	Port    int            `yaml:"port"`
	Options map[string]any `yaml:"options"`
}

// EngagementConfig configures how interactions are stitched together.
type EngagementConfig struct {
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

// AlertConfig configures outward notification.
type AlertConfig struct {
	// MinSeverity gates what leaves the platform. Deception's promise is a
	// small number of certain alerts; forwarding every probe breaks it.
	MinSeverity string       `yaml:"min_severity"`
	Sinks       []SinkConfig `yaml:"sinks"`
}

// SinkConfig selects and configures one alert destination.
type SinkConfig struct {
	Driver string         `yaml:"driver"`
	Config map[string]any `yaml:"config"`
}

// StorageConfig configures the evidence store.
type StorageConfig struct {
	EvidenceFile string `yaml:"evidence_file"`
	MemoryWindow int    `yaml:"memory_window"`
	SyncEvery    int    `yaml:"sync_every"`
}

// DriverConfig selects which drivers back each abstraction.
type DriverConfig struct {
	Compute string `yaml:"compute"`
}

// Load reads, expands and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse validates configuration from bytes.
func Parse(raw []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a typo in a key must fail loudly, not be ignored
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Tenant == "" {
		c.Tenant = "default"
	}
	if c.Site == "" {
		c.Site = "default"
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:8422"
	}
	if c.API.PublicURL == "" {
		c.API.PublicURL = "http://" + c.API.Listen
	}
	if c.Honeyd.Bind == "" {
		c.Honeyd.Bind = "0.0.0.0"
	}
	if c.Honeyd.MaxSessionDuration == 0 {
		c.Honeyd.MaxSessionDuration = 30 * time.Minute
	}
	if c.Honeyd.IdleTimeout == 0 {
		c.Honeyd.IdleTimeout = 5 * time.Minute
	}
	if c.Honeyd.MaxTranscriptBytes == 0 {
		c.Honeyd.MaxTranscriptBytes = 256 * 1024
	}
	if c.Honeyd.MaxConnsPerIP == 0 {
		c.Honeyd.MaxConnsPerIP = 25
	}
	if c.Honeyd.MaxConnsTotal == 0 {
		c.Honeyd.MaxConnsTotal = 2000
	}
	if c.Engagement.IdleTimeout == 0 {
		c.Engagement.IdleTimeout = 30 * time.Minute
	}
	if c.Alerts.MinSeverity == "" {
		c.Alerts.MinSeverity = "high"
	}
	if len(c.Alerts.Sinks) == 0 {
		c.Alerts.Sinks = []SinkConfig{{Driver: "stdout"}}
	}
	if c.Storage.EvidenceFile == "" {
		c.Storage.EvidenceFile = filepath.Join(c.DataDir, "evidence.jsonl")
	}
	if c.Storage.MemoryWindow == 0 {
		c.Storage.MemoryWindow = 200_000
	}
	if c.Storage.SyncEvery == 0 {
		c.Storage.SyncEvery = 1
	}
	if c.Drivers.Compute == "" {
		c.Drivers.Compute = "inproc"
	}
	if c.Tokens.File == "" {
		c.Tokens.File = filepath.Join(c.DataDir, "tokens.json")
	}
	if c.Tokens.BaseURL == "" {
		// Fall back to the first tokens listener, if the deployment has one.
		for _, d := range c.Honeyd.Decoys {
			for _, s := range d.Services {
				if s.Service == "tokens" {
					host := c.Honeyd.Bind
					if len(d.Addresses) > 0 {
						host = d.Addresses[0]
					}
					if host == "0.0.0.0" || host == "" {
						host = "127.0.0.1"
					}
					c.Tokens.BaseURL = fmt.Sprintf("http://%s:%d", host, s.Port)
				}
			}
		}
	}
}

// Validate rejects configurations that would produce a broken or dangerous
// deployment. Errors name the offending decoy and service, because an operator
// reading them is usually looking at a hundred-line file.
func (c *Config) Validate() error {
	if len(c.Honeyd.Decoys) == 0 {
		return fmt.Errorf("config: no decoys defined; a deployment with no decoys observes nothing")
	}

	seenID := map[string]bool{}
	seenBind := map[string]string{}
	for i, d := range c.Honeyd.Decoys {
		if d.ID == "" {
			return fmt.Errorf("config: decoy %d has no id", i)
		}
		if seenID[d.ID] {
			return fmt.Errorf("config: duplicate decoy id %q", d.ID)
		}
		seenID[d.ID] = true

		if d.Persona == "" {
			return fmt.Errorf("config: decoy %q has no persona (available: %s)",
				d.ID, strings.Join(honeyd.PersonaNames(), ", "))
		}
		if _, err := honeyd.BuildPersona(d.Persona, "validate"); err != nil {
			return fmt.Errorf("config: decoy %q: %w", d.ID, err)
		}
		if len(d.Services) == 0 {
			return fmt.Errorf("config: decoy %q has no services", d.ID)
		}
		for _, a := range d.Addresses {
			if net.ParseIP(a) == nil {
				return fmt.Errorf("config: decoy %q: %q is not a valid IP address", d.ID, a)
			}
		}
		for _, s := range d.Services {
			if !isKnownService(s.Service) {
				return fmt.Errorf("config: decoy %q: unknown service %q (available: %s)",
					d.ID, s.Service, strings.Join(honeyd.ServiceNames(), ", "))
			}
			if s.Port < 1 || s.Port > 65535 {
				return fmt.Errorf("config: decoy %q service %q: port %d is out of range",
					d.ID, s.Service, s.Port)
			}
			for _, a := range addressesOf(d, c.Honeyd.Bind) {
				bind := net.JoinHostPort(a, strconv.Itoa(s.Port))
				if owner, dup := seenBind[bind]; dup {
					return fmt.Errorf("config: %s is claimed by both %q and %q",
						bind, owner, d.ID+"/"+s.Service)
				}
				seenBind[bind] = d.ID + "/" + s.Service
			}
		}
	}

	if _, err := ParseSeverity(c.Alerts.MinSeverity); err != nil {
		return err
	}
	for i, s := range c.Alerts.Sinks {
		if s.Driver == "" {
			return fmt.Errorf("config: alert sink %d has no driver", i)
		}
	}
	return nil
}

func isKnownService(name string) bool {
	for _, s := range honeyd.ServiceNames() {
		if s == name {
			return true
		}
	}
	return false
}

// ParseSeverity converts a configured severity name.
func ParseSeverity(s string) (event.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "informational", "info":
		return event.SeverityInformational, nil
	case "low":
		return event.SeverityLow, nil
	case "medium":
		return event.SeverityMedium, nil
	case "high":
		return event.SeverityHigh, nil
	case "critical":
		return event.SeverityCritical, nil
	case "fatal":
		return event.SeverityFatal, nil
	default:
		return 0, fmt.Errorf("config: unknown severity %q (use informational, low, medium, high, critical or fatal)", s)
	}
}

// addressesOf returns the addresses a decoy occupies, falling back to the
// farm's bind address when it declares none.
func addressesOf(d DecoyConfig, bind string) []string {
	if len(d.Addresses) == 0 {
		return []string{bind}
	}
	return d.Addresses
}

// Listeners flattens the decoy definitions into honeyd listeners, one per
// address and service.
func (c *Config) Listeners() []honeyd.ListenerConfig {
	var out []honeyd.ListenerConfig
	for _, d := range c.Honeyd.Decoys {
		for _, addr := range addressesOf(d, c.Honeyd.Bind) {
			for _, s := range d.Services {
				lc := honeyd.ListenerConfig{
					Service: s.Service, Port: s.Port, Persona: d.Persona,
					DecoyID: d.ID, Options: s.Options,
				}
				// Only pin the address when the decoy asked for specific ones;
				// otherwise the farm's bind address applies.
				if len(d.Addresses) > 0 {
					lc.Address = addr
				}
				out = append(out, lc)
			}
		}
	}
	return out
}

// ProjectedAddresses reports every address the deployment occupies, which is
// the number an operator cares about when asking "how much of my subnet does
// this cover?".
func (c *Config) ProjectedAddresses() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range c.Honeyd.Decoys {
		for _, a := range addressesOf(d, c.Honeyd.Bind) {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// HoneydConfig builds the farm configuration.
func (c *Config) HoneydConfig() honeyd.Config {
	return honeyd.Config{
		Identity: honeyd.Identity{
			TenantID: c.Tenant, SiteID: c.Site, DecoyID: "unassigned",
		},
		DeploySeed:         c.DeploySeed,
		BindAddr:           c.Honeyd.Bind,
		Listeners:          c.Listeners(),
		MaxSessionDuration: c.Honeyd.MaxSessionDuration,
		IdleTimeout:        c.Honeyd.IdleTimeout,
		MaxTranscriptBytes: c.Honeyd.MaxTranscriptBytes,
		MaxConnsPerIP:      c.Honeyd.MaxConnsPerIP,
		MaxConnsTotal:      c.Honeyd.MaxConnsTotal,
	}
}

// EnsureSeed loads a persisted deployment seed or creates one. A stable seed is
// what keeps a decoy's hostname, planted secrets and file timestamps identical
// across restarts; a fresh seed on every start would be an obvious tell.
func (c *Config) EnsureSeed() error {
	if c.DeploySeed != "" {
		return nil
	}
	path := filepath.Join(c.DataDir, "deploy.seed")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		c.DeploySeed = strings.TrimSpace(string(b))
		return nil
	}
	if err := os.MkdirAll(c.DataDir, 0o750); err != nil {
		return fmt.Errorf("config: create data dir: %w", err)
	}
	c.DeploySeed = event.NewID() + event.NewID()
	if err := os.WriteFile(path, []byte(c.DeploySeed), 0o600); err != nil {
		return fmt.Errorf("config: persist deployment seed: %w", err)
	}
	return nil
}

// Warnings returns non-fatal issues worth telling the operator about. These are
// the mistakes that do not break startup but do undermine the deployment.
func (c *Config) Warnings() []string {
	var w []string
	host, _, _ := strings.Cut(c.API.Listen, ":")
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		w = append(w, fmt.Sprintf(
			"the management API is bound to %s: expose it only on a management network, never on the decoy segment (docs/04)",
			c.API.Listen))
	}
	if c.API.Token == "" && host != "127.0.0.1" && host != "localhost" {
		w = append(w, "the management API has no token set while listening off-loopback: anyone who can reach it can read all evidence")
	}
	if sev, err := ParseSeverity(c.Alerts.MinSeverity); err == nil && sev <= event.SeverityLow {
		w = append(w, "alerts.min_severity is low: forwarding every probe to your SIEM defeats the point of deception")
	}
	privileged := 0
	for _, d := range c.Honeyd.Decoys {
		for _, s := range d.Services {
			if s.Port < 1024 {
				privileged++
			}
		}
	}
	if privileged > 0 {
		w = append(w, fmt.Sprintf(
			"%d service(s) use privileged ports: run behind a port redirect rather than as root (see profiles/README.md)",
			privileged))
	}
	return w
}
