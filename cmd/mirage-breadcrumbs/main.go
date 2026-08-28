// Command mirage-breadcrumbs seeds a real endpoint with lures that lead into
// the decoys.
//
// It runs where an attacker lands -- a workstation, a jump box, a build agent --
// not where the decoys live. It mints honeytokens from the director so the
// director's watcher knows them, renders endpoint-appropriate lures (a saved
// .rdp file, an ~/.aws profile, a line of shell history) that point at decoys,
// and writes them to this machine. When the attacker harvests one and follows
// it, the honeynet catches them, and the trail names the endpoint it started on.
//
// Three commands: `plan` prints what would be placed and changes nothing;
// `apply` mints the tokens and writes the lures, recording a manifest; `remove`
// reverses a manifest exactly. It writes to a machine MIRAGE does not own, so it
// never overwrites a real file and never plants a real secret -- see
// internal/breadcrumbs for the invariants.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sauron666/Honeypot/internal/breadcrumbs"
	"github.com/sauron666/Honeypot/internal/tokens"
	"github.com/sauron666/Honeypot/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		os.Stdout.WriteString(usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "plan":
		err = run(os.Args[2:], false)
	case "apply":
		err = run(os.Args[2:], true)
	case "remove":
		err = remove(os.Args[2:])
	case "version":
		fmt.Println(version.String() + " (breadcrumbs)")
	case "-h", "--help", "help":
		os.Stdout.WriteString(usage)
	default:
		fmt.Fprintf(os.Stderr, "mirage-breadcrumbs: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mirage-breadcrumbs: %v\n", err)
		os.Exit(1)
	}
}

const usage = `mirage-breadcrumbs - seed an endpoint with lures leading into the decoys

usage:
  mirage-breadcrumbs plan   --config crumbs.yaml
  mirage-breadcrumbs apply  --config crumbs.yaml [--manifest out.json]
  mirage-breadcrumbs remove --manifest out.json

plan changes nothing; apply mints honeytokens from the director and writes the
lures; remove reverses exactly what a manifest recorded.

config (yaml):
  director: http://mirage.example:8422   # where to mint tokens; omit for --offline
  token:    ...                          # API bearer token, if the director needs one
  target:
    os:   linux                          # or windows; default: this host's OS
    home: /home/alice                    # default: $HOME or %USERPROFILE%
    user: alice
  decoys:
    - {id: dcy-dc01,  host: dc01.corp.local,  service: rdp,   user: administrator}
    - {id: dcy-sql01, host: sql01.corp.local, service: mssql}
`

// config is the breadcrumbs manifest.
type config struct {
	Director string `yaml:"director"`
	Token    string `yaml:"token"`
	Offline  bool   `yaml:"offline"`
	Target   struct {
		OS   string `yaml:"os"`
		Home string `yaml:"home"`
		User string `yaml:"user"`
	} `yaml:"target"`
	Decoys []breadcrumbs.Decoy `yaml:"decoys"`
}

func run(args []string, apply bool) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the breadcrumbs config (required)")
	manifestPath := fs.String("manifest", "breadcrumbs-manifest.json", "where apply writes its manifest")
	root := fs.String("root", "", "write under this directory instead of the real filesystem (for testing)")
	offline := fs.Bool("offline", false, "mint tokens into a local store instead of the director")
	fs.Parse(args)

	if *cfgPath == "" {
		return fmt.Errorf("--config is required")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	tgt := resolveTarget(cfg)

	minter, closeMinter, err := buildMinter(cfg, *offline)
	if err != nil {
		return err
	}
	defer closeMinter()

	planner := breadcrumbs.NewPlanner(minter)
	crumbs, err := planner.Plan(cfg.Decoys, tgt)
	if err != nil {
		return err
	}

	if !apply {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KIND\tPATH\tLEADS TO")
		for _, c := range crumbs {
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.Kind, c.Path, c.Explain)
		}
		w.Flush()
		fmt.Printf("\n%d lure(s) would be planted for %s. Nothing was written or minted.\n",
			len(crumbs), tgt.User)
		fmt.Println("Run `apply` to mint the honeytokens and place them.")
		return nil
	}

	planter := breadcrumbs.NewPlanter(*root)
	host, _ := os.Hostname()
	manifest, err := planter.PlaceAll(crumbs, host, tgt.User)
	if err != nil {
		return err
	}
	if err := breadcrumbs.SaveManifest(manifest, *manifestPath); err != nil {
		return fmt.Errorf("the lures were placed but the manifest could not be saved (%w); "+
			"remove them by hand or MIRAGE cannot clean them up later", err)
	}
	fmt.Printf("Planted %d lure(s) on %s. Manifest: %s\n", len(manifest.Placed), host, *manifestPath)
	fmt.Println("Keep the manifest: `remove --manifest` reverses exactly what was placed.")
	return nil
}

func remove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	manifestPath := fs.String("manifest", "breadcrumbs-manifest.json", "the manifest to reverse")
	root := fs.String("root", "", "the root apply used, if any")
	fs.Parse(args)

	m, err := breadcrumbs.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	planter := breadcrumbs.NewPlanter(*root)
	if err := planter.Remove(m); err != nil {
		return err
	}
	fmt.Printf("Removed %d lure(s) recorded in %s.\n", len(m.Placed), *manifestPath)
	return nil
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Decoys) == 0 {
		return nil, fmt.Errorf("no decoys declared; there is nothing to lead an attacker to")
	}
	return &cfg, nil
}

func resolveTarget(cfg *config) breadcrumbs.Target {
	tgt := breadcrumbs.Target{
		OS:   breadcrumbs.OS(cfg.Target.OS),
		Home: cfg.Target.Home,
		User: cfg.Target.User,
	}
	if tgt.OS == "" {
		if runtime.GOOS == "windows" {
			tgt.OS = breadcrumbs.Windows
		} else {
			tgt.OS = breadcrumbs.Linux
		}
	}
	if tgt.Home == "" {
		if h := os.Getenv("HOME"); h != "" {
			tgt.Home = h
		} else if h := os.Getenv("USERPROFILE"); h != "" {
			tgt.Home = h
		}
	}
	if tgt.User == "" {
		if u := os.Getenv("USER"); u != "" {
			tgt.User = u
		} else if u := os.Getenv("USERNAME"); u != "" {
			tgt.User = u
		}
	}
	return tgt
}

// buildMinter returns a minter and a cleanup. Offline mode mints into a local
// token store (useful for a dry run or a fully self-contained lab); the default
// mints through the director's API so the director's watcher knows the tokens.
func buildMinter(cfg *config, offline bool) (breadcrumbs.Minter, func(), error) {
	if offline || cfg.Offline {
		store, err := tokens.NewStore("breadcrumbs-tokens.json", "http://127.0.0.1:8081")
		if err != nil {
			return nil, func() {}, err
		}
		return store, func() {}, nil
	}
	if cfg.Director == "" {
		return nil, func() {}, fmt.Errorf("no director configured; set `director:` or use --offline")
	}
	return &apiMinter{base: strings.TrimRight(cfg.Director, "/"), token: cfg.Token,
		client: &http.Client{Timeout: 15 * time.Second}}, func() {}, nil
}

// apiMinter mints tokens through a running director, so every breadcrumb the
// agent plants is one the director's watcher is already looking for.
type apiMinter struct {
	base   string
	token  string
	client *http.Client
}

func (a *apiMinter) Mint(typ tokens.Type, label, location string) (*tokens.Token, error) {
	body, _ := json.Marshal(map[string]string{
		"type": string(typ), "label": label, "location": location,
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		a.base+"/api/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("minting from the director failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("director refused to mint a %s token: %s: %s",
			typ, resp.Status, strings.TrimSpace(string(msg)))
	}
	var tok tokens.Token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, err
	}
	return &tok, nil
}
