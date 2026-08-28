// Command miragectl is the MIRAGE command-line tool: configuration checks,
// offline evidence verification and queries against a running director.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/driverset"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/farm"
	"github.com/sauron666/Honeypot/internal/forge"
	"github.com/sauron666/Honeypot/internal/honeyd"
	"github.com/sauron666/Honeypot/internal/presence"
	"github.com/sauron666/Honeypot/internal/store"
	"github.com/sauron666/Honeypot/internal/version"
)

const usage = `miragectl - MIRAGE deception platform

usage: miragectl <command> [flags]

commands:
  doctor      validate a configuration and the driver set
  personas    list available decoy personas
  services    list available emulated services
  drivers     list registered drivers and their capabilities
  verify      replay an evidence file's hash chain
  events      query an evidence file offline
  forge       turn a recorded engagement into Sigma, Suricata, YARA and STIX
  tokens      list, mint or delete honeytokens through a running director
  plan        show what applying a manifest would change, without doing it
  apply       reconcile a running director with a manifest, without a restart
  fingerprint score how identifiable each decoy is, and say what gives it away
  assure      run the self-test: attack the deployment and verify it detected it
  presence-ca issue the mutual-TLS material for the overlay hub and its agents
  economics   ROI metrics: attacker hours consumed, confirmed incidents, top techniques
  vms         list full-OS decoys, and burn or reset one during an incident
  status      query a running director over its API
  version     print the version

run "miragectl <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "doctor":
		err = doctor(args)
	case "personas":
		err = listPersonas()
	case "services":
		err = listServices()
	case "drivers":
		err = listDrivers()
	case "verify":
		err = verify(args)
	case "events":
		err = events(args)
	case "tokens":
		err = tokensCmd(args)
	case "forge":
		err = forgeCmd(args)
	case "plan":
		err = planApply(args, false)
	case "apply":
		err = planApply(args, true)
	case "fingerprint":
		err = fingerprintCmd(args)
	case "assure":
		err = assureCmd(args)
	case "presence-ca":
		err = presenceCA(args)
	case "economics":
		err = economicsCmd(args)
	case "vms":
		err = vmsCmd(args)
	case "status":
		err = status(args)
	case "version":
		fmt.Println(version.String())
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "miragectl: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "miragectl %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// doctor is the pre-flight check: it catches the configuration mistakes that
// would otherwise be discovered during an incident.
func doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	path := fs.String("config", "profiles/p0-box.yaml", "configuration file")
	fs.Parse(args)

	problems := 0
	fmt.Printf("%s\n\n", version.String())

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Printf("  [FAIL] configuration: %v\n", err)
		return fmt.Errorf("configuration is not usable")
	}
	fmt.Printf("  [ ok ] configuration %s\n", *path)
	fmt.Printf("         tenant=%s site=%s decoys=%d listeners=%d\n",
		cfg.Tenant, cfg.Site, len(cfg.Honeyd.Decoys), len(cfg.Listeners()))

	for _, w := range cfg.Warnings() {
		fmt.Printf("  [warn] %s\n", w)
		problems++
	}

	reg := driverset.Default()
	defer reg.Close()
	if coverage := reg.CheckCoverage(); len(coverage) > 0 {
		for _, c := range coverage {
			fmt.Printf("  [warn] %s\n", c)
			problems++
		}
	} else {
		fmt.Printf("  [ ok ] driver coverage: no single-implementation categories\n")
	}

	for _, sc := range cfg.Alerts.Sinks {
		sink, err := reg.Sink(sc.Driver, sc.Config)
		if err != nil {
			fmt.Printf("  [FAIL] alert sink %q: %v\n", sc.Driver, err)
			problems++
			continue
		}
		if err := sink.Probe(context.Background()); err != nil {
			fmt.Printf("  [warn] alert sink %q unreachable: %v\n", sc.Driver, err)
			problems++
			continue
		}
		fmt.Printf("  [ ok ] alert sink %q reachable\n", sc.Driver)
	}

	// Full-OS decoys are the part of a deployment that can hurt somebody, so
	// doctor checks the whole chain here rather than leaving it to startup:
	// the compute driver, the fabric driver, and what the fabric actually says
	// about containment right now.
	if len(cfg.VMs.Decoys) > 0 {
		problems += checkVMFarm(reg, cfg)
	}

	// Ports are the most common startup failure, so check them before the
	// operator discovers it at 3am.
	for _, l := range cfg.Listeners() {
		if l.Port < 1024 && os.Geteuid() != 0 {
			fmt.Printf("  [warn] %s/%d needs root or a port redirect\n", l.Service, l.Port)
			problems++
		}
	}

	fmt.Println()
	if problems == 0 {
		fmt.Println("no problems found.")
		return nil
	}
	fmt.Printf("%d item(s) need attention.\n", problems)
	return nil
}

func listPersonas() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PERSONA\tHOSTNAME\tOS\tUPTIME\tSERVICES SUGGESTED")
	for _, name := range honeyd.PersonaNames() {
		p, err := honeyd.BuildPersona(name, "preview")
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%.0fd\t%s\n", name, p.Hostname, p.OSName,
			time.Since(p.BootTime).Hours()/24, suggestedServices(name))
	}
	return w.Flush()
}

func suggestedServices(persona string) string {
	switch persona {
	case "linux/web":
		return "ssh, http, ftp, smtp"
	case "linux/db":
		return "ssh, mysql, mssql, redis"
	case "linux/backup":
		return "ssh, ftp, telnet"
	case "windows/dc":
		return "ldap, smb (kerberoast, AS-REP, ADCS and LAPS bait)"
	case "linux/fileserver":
		return "ftp, smb, ssh (ransomware engine watches the share)"
	default:
		return "ssh"
	}
}

func listServices() error {
	names := honeyd.ServiceNames()
	sort.Strings(names)
	desc := map[string]string{
		"ssh":     "real SSH server; captures credentials, keys, commands and client fingerprints",
		"telnet":  "telnet login and shell; catches IoT botnet loaders",
		"http":    "web portal; detects scanners, injection, log4shell and captures form credentials",
		"ftp":     "FTP with passive data transfers; records downloads and captures uploads",
		"redis":   "unauthenticated Redis; captures the CONFIG SET / SAVE takeover chain",
		"generic": "any TCP port; records banners, payloads and bare port scans",
		"mysql":   "real MySQL protocol; verifies planted passwords and records crackable scrambles",
		"mssql":   "TDS login; recovers the plaintext password TDS only obfuscates",
		"vnc":     "RFB with VNC auth; records the DES challenge and response",
		"smtp":    "mail server that never delivers; captures credentials and open-relay probes",
		"snmp":    "SNMP v1/v2c over UDP; records community strings, never amplifies",
		"mcp":     "honey MCP server; catches AI agents and attackers discovering internal tools",
		"kerberos": "decoy KDC; sees enumeration, spraying and roasting as ticket requests, " +
			"and hands out hashes that crack to a watched password",
		"modbus": "Modbus/TCP PLC; reads are recon, writes are treated as process manipulation",
		"smb":    "SMB2 negotiation and NTLM; captures NetNTLMv2 hashes and the attacker's workstation name",
		"ldap":   "decoy Active Directory; cleartext bind passwords, kerberoast/AS-REP/ADCS/LAPS enumeration",
		"tokens": "honeytoken callback receiver; must be reachable by whoever found the token",
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SERVICE\tDESCRIPTION")
	for _, n := range names {
		fmt.Fprintf(w, "%s\t%s\n", n, desc[n])
	}
	return w.Flush()
}

func listDrivers() error {
	reg := driverset.Default()
	defer reg.Close()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tNAME\tCAPABILITIES\tSUMMARY")
	for _, i := range reg.Available() {
		caps := make([]string, 0, len(i.Capabilities))
		for _, c := range i.Capabilities {
			caps = append(caps, strings.TrimPrefix(string(c), string(i.Kind)+"."))
		}
		if len(caps) == 0 {
			caps = []string{"-"}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", i.Kind, i.Name, strings.Join(caps, ","), i.Summary)
	}
	return w.Flush()
}

// verify replays an evidence file offline. This is what an analyst runs before
// handing evidence to anyone else.
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("file", "data/evidence.jsonl", "evidence file")
	fs.Parse(args)

	st, err := store.OpenFile(*path, store.FileOptions{MemoryWindow: 1, SyncEvery: 0})
	if err != nil {
		return err
	}
	defer st.Close()

	start := time.Now()
	if err := st.Verify(context.Background()); err != nil {
		fmt.Printf("EVIDENCE TAMPERED\n  %v\n", err)
		os.Exit(1)
	}
	s := st.Stats()
	fmt.Printf("evidence intact\n  file      %s\n  events    %d\n  head seq  %d\n  head hash %s\n  took      %s\n",
		*path, s.Events, s.HeadSeq, s.HeadHash, time.Since(start).Round(time.Millisecond))
	return nil
}

func events(args []string) error {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	path := fs.String("file", "data/evidence.jsonl", "evidence file")
	limit := fs.Int("limit", 50, "maximum events to show")
	sev := fs.String("severity", "", "minimum severity")
	search := fs.String("q", "", "substring search")
	svc := fs.String("service", "", "filter by service")
	src := fs.String("src", "", "filter by source IP")
	asJSON := fs.Bool("json", false, "emit raw JSON lines")
	fs.Parse(args)

	st, err := store.OpenFile(*path, store.FileOptions{MemoryWindow: 500_000, SyncEvery: 0})
	if err != nil {
		return err
	}
	defer st.Close()

	q := store.Query{Limit: *limit, Search: *search, Service: *svc, SrcIP: *src}
	if *sev != "" {
		s, err := config.ParseSeverity(*sev)
		if err != nil {
			return err
		}
		q.MinSeverity = s
	}
	evs, err := st.Query(context.Background(), q)
	if err != nil {
		return err
	}
	if *asJSON {
		for _, e := range evs {
			b, _ := event.CanonicalJSON(e)
			fmt.Println(string(b))
		}
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tSEV\tSOURCE\tSERVICE\tMESSAGE")
	for _, e := range evs {
		srcIP := "-"
		if e.Src != nil {
			srcIP = e.Src.IP
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp().Format("15:04:05"), e.SeverityID, srcIP,
			orDash(e.Mirage.Service), truncate(e.Message, 90))
	}
	return w.Flush()
}

// tokensCmd manages honeytokens through a running director.
func tokensCmd(args []string) error {
	fs := flag.NewFlagSet("tokens", flag.ExitOnError)
	addr := fs.String("api", "http://127.0.0.1:8422", "director API base URL")
	token := fs.String("token", "", "bearer token, if the API requires one")
	mint := fs.String("mint", "", "mint a token of this type (url, aws-key, office-doc, ...)")
	label := fs.String("label", "", "human label for the minted token")
	location := fs.String("location", "", "where the token will be planted")
	del := fs.String("delete", "", "delete the token with this id")
	fs.Parse(args)

	switch {
	case *mint != "":
		body, _ := json.Marshal(map[string]string{
			"type": *mint, "label": *label, "location": *location,
		})
		raw, err := apiDo(http.MethodPost, *addr+"/api/tokens", *token, body)
		if err != nil {
			return err
		}
		var t map[string]any
		if err := json.Unmarshal(raw, &t); err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(t); err != nil {
			return err
		}
		if id, ok := t["id"].(string); ok && *mint == "office-doc" {
			fmt.Printf("\nfetch the bait document with:\n  curl -OJ %s/api/tokens/%s/docx\n", *addr, id)
		}
		return nil

	case *del != "":
		_, err := apiDo(http.MethodDelete, *addr+"/api/tokens/"+*del, *token, nil)
		if err != nil {
			return err
		}
		fmt.Printf("deleted %s\n", *del)
		return nil
	}

	raw, err := apiGet(*addr+"/api/tokens", *token)
	if err != nil {
		return err
	}
	var resp struct {
		Tokens []struct {
			ID, Type, Label, Value, Location string
			Triggers                         int
		} `json:"tokens"`
		Total, Triggered int
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID	TYPE	TRIGGERS	LABEL	PLANTED AT	VALUE")
	for _, t := range resp.Tokens {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n",
			t.ID, t.Type, t.Triggers, orDash(t.Label), orDash(t.Location), truncate(t.Value, 44))
	}
	w.Flush()
	fmt.Printf("\n%d token(s), %d triggered\n", resp.Total, resp.Triggered)
	return nil
}

// forgeCmd generates detection content from a recorded engagement, offline.
//
// It works straight from the evidence file, so an analyst can produce rules and
// a report for an incident from months ago without a running director.
func forgeCmd(args []string) error {
	fs := flag.NewFlagSet("forge", flag.ExitOnError)
	path := fs.String("file", "data/evidence.jsonl", "evidence file")
	engID := fs.String("engagement", "", "engagement id (default: the highest-risk one in the file)")
	outDir := fs.String("out", "", "write the artifacts into this directory instead of stdout")
	fs.Parse(args)

	st, err := store.OpenFile(*path, store.FileOptions{MemoryWindow: 500_000, SyncEvery: 0})
	if err != nil {
		return err
	}
	defer st.Close()

	all, err := st.Query(context.Background(), store.Query{Limit: 1_000_000, Ascending: true})
	if err != nil {
		return err
	}
	engagements := engagement.FromEvents(all)
	if len(engagements) == 0 {
		return fmt.Errorf("no engagements in %s", *path)
	}

	eng := engagements[0] // FromEvents sorts by risk
	if *engID != "" {
		eng = nil
		for _, e := range engagements {
			if e.ID == *engID {
				eng = e
			}
		}
		if eng == nil {
			return fmt.Errorf("engagement %q is not in %s", *engID, *path)
		}
	}

	var events []*event.Event
	for _, e := range all {
		if e.Mirage.EngagementID == eng.ID {
			events = append(events, e)
		}
	}
	bundle := forge.New().Build(eng, events)

	if *outDir == "" {
		fmt.Print(bundle.Report)
		fmt.Printf("\n---\n\n%d rule(s) generated, %d candidate(s) rejected. "+
			"Re-run with -out <dir> to write them.\n", len(bundle.Rules), len(bundle.Rejected))
		return nil
	}
	return writeBundle(*outDir, eng.ID, bundle)
}

func writeBundle(dir, engID string, b *forge.Bundle) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	write := func(name, content string) error {
		if strings.TrimSpace(content) == "" {
			return nil
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
			return err
		}
		fmt.Printf("  wrote %s\n", p)
		return nil
	}

	var sigma, suricata, yara strings.Builder
	for _, r := range b.Rules {
		switch r.Format {
		case forge.FormatSigma:
			sigma.WriteString(r.Content + "\n")
		case forge.FormatSuricata:
			suricata.WriteString(r.Content + "\n")
		case forge.FormatYARA:
			yara.WriteString(r.Content + "\n")
		}
	}
	for _, f := range []struct{ name, content string }{
		{"report.md", b.Report},
		{"sigma-" + engID + ".yml", sigma.String()},
		{"suricata-" + engID + ".rules", suricata.String()},
		{"captured-" + engID + ".yar", yara.String()},
		{"stix-" + engID + ".json", b.STIX},
	} {
		if err := write(f.name, f.content); err != nil {
			return err
		}
	}

	var iocs strings.Builder
	for _, i := range b.IOCs {
		fmt.Fprintf(&iocs, "%s\t%s\t%s\n", i.Type, i.Value, i.Context)
	}
	if err := write("iocs-"+engID+".tsv", iocs.String()); err != nil {
		return err
	}

	fmt.Printf("\n%d rule(s), %d indicator(s), %d rejected candidate(s).\n",
		len(b.Rules), len(b.IOCs), len(b.Rejected))
	return nil
}

// planApply implements deception-as-code: compare a manifest against what is
// running, and optionally reconcile.
//
// Deception changes what an attacker sees, so being able to review a change
// before making it matters more here than in most infrastructure.
func planApply(args []string, apply bool) error {
	name := "plan"
	if apply {
		name = "apply"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("config", "profiles/p0-box.yaml", "manifest to apply")
	addr := fs.String("api", "http://127.0.0.1:8422", "director API base URL")
	token := fs.String("token", "", "bearer token, if the API requires one")
	fs.Parse(args)

	// Validate locally first: a manifest that will not parse should fail here,
	// not after a round trip.
	if _, err := config.Load(*path); err != nil {
		return err
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}

	endpoint := "/api/config/plan"
	if apply {
		endpoint = "/api/config/apply"
	}
	body, err := apiDo(http.MethodPost, *addr+endpoint, *token, raw)
	if err != nil {
		return err
	}

	var resp struct {
		Plan struct {
			Changes []struct {
				Action  string `json:"action"`
				Key     string `json:"key"`
				DecoyID string `json:"decoy_id"`
				Persona string `json:"persona"`
				Detail  string `json:"detail"`
			}
			RequiresRestart []string `json:"requires_restart"`
			Unchanged       int
		}
		Summary        string
		Applied        bool
		Added, Removed []string
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	if len(resp.Plan.Changes) == 0 {
		fmt.Printf("%s\n", resp.Summary)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ACTION\tENDPOINT\tDECOY\tPERSONA\tDETAIL")
		for _, c := range resp.Plan.Changes {
			marker := map[string]string{"add": "+", "remove": "-", "replace": "~"}[c.Action]
			fmt.Fprintf(w, "%s %s\t%s\t%s\t%s\t%s\n",
				marker, c.Action, c.Key, orDash(c.DecoyID), orDash(c.Persona), c.Detail)
		}
		w.Flush()
		fmt.Printf("\n%s\n", resp.Summary)
	}

	for _, r := range resp.Plan.RequiresRestart {
		fmt.Printf("  restart required: %s\n", r)
	}
	if !apply && len(resp.Plan.Changes) > 0 {
		fmt.Printf("\nrun \"miragectl apply -config %s\" to make these changes\n", *path)
	}
	if apply && resp.Applied {
		fmt.Printf("applied: %d endpoint(s) added, %d removed\n", len(resp.Added), len(resp.Removed))
	}
	return nil
}

// fingerprintCmd asks the director to attack its own decoys the way a careful
// operator would when deciding whether a host is real.
func fingerprintCmd(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	addr := fs.String("api", "http://127.0.0.1:8422", "director API base URL")
	token := fs.String("token", "", "bearer token, if the API requires one")
	verbose := fs.Bool("v", false, "show the fix for every finding")
	fs.Parse(args)

	raw, err := apiDoTimeout(http.MethodPost, *addr+"/api/assure/fingerprint", *token,
		[]byte("{}"), 3*time.Minute)
	if err != nil {
		return err
	}
	var rep struct {
		Decoys []struct {
			DecoyID  string `json:"decoy_id"`
			Persona  string `json:"persona"`
			Score    int    `json:"score"`
			Verdict  string `json:"verdict"`
			Findings []struct {
				Check, Detail, Fix string
				Weight             int
			} `json:"findings"`
		}
		WorstScore int    `json:"worst_score"`
		Summary    string `json:"summary"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	for _, d := range rep.Decoys {
		fmt.Printf("\n%-16s %3d/100  %s  (%s)\n", d.DecoyID, d.Score, d.Verdict, d.Persona)
		for _, f := range d.Findings {
			fmt.Printf("    +%-3d %-26s %s\n", f.Weight, f.Check, f.Detail)
			if *verbose && f.Fix != "" {
				fmt.Printf("         fix: %s\n", f.Fix)
			}
		}
		if len(d.Findings) == 0 {
			fmt.Printf("    nothing found\n")
		}
	}
	fmt.Printf("\n%s\n", rep.Summary)
	if !*verbose {
		fmt.Printf("run with -v to see how to fix each finding\n")
	}
	return nil
}

// assureCmd runs the deception self-test through a running director.
func assureCmd(args []string) error {
	fs := flag.NewFlagSet("assure", flag.ExitOnError)
	addr := fs.String("api", "http://127.0.0.1:8422", "director API base URL")
	token := fs.String("token", "", "bearer token, if the API requires one")
	fs.Parse(args)

	raw, err := apiDoTimeout(http.MethodPost, *addr+"/api/assure", *token, []byte("{}"), 3*time.Minute)
	if err != nil && !strings.Contains(err.Error(), "503") {
		return err
	}
	if raw == nil {
		return err
	}
	var rep struct {
		Results []struct {
			Scenario, Service, Why, Reason, Error string
			Acted, Recorded, Skipped              bool
			Latency                               int64 `json:"latency_ns"`
			Events                                int
		}
		Passed, Failed, Skipped int
		Healthy                 bool
		Summary                 string
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RESULT\tSCENARIO\tSERVICE\tLATENCY\tEVENTS\tDETAIL")
	for _, r := range rep.Results {
		status, detail := "PASS", ""
		switch {
		case r.Skipped:
			status, detail = "skip", r.Reason
		case !r.Acted:
			status, detail = "FAIL", "the decoy did not answer: "+r.Error
		case !r.Recorded:
			status, detail = "FAIL", r.Error
		}
		latency := "-"
		if r.Latency > 0 {
			latency = time.Duration(r.Latency).Round(time.Millisecond).String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			status, r.Scenario, r.Service, latency, r.Events, detail)
	}
	w.Flush()

	fmt.Printf("\n%s\n", rep.Summary)
	if !rep.Healthy {
		// A silent honeypot is worse than none, so a failed self-test must be
		// visible to whatever is running this.
		os.Exit(1)
	}
	return nil
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	addr := fs.String("api", "http://127.0.0.1:8422", "director API base URL")
	token := fs.String("token", "", "bearer token, if the API requires one")
	fs.Parse(args)

	body, err := apiGet(*addr+"/api/stats", *token)
	if err != nil {
		return err
	}
	var s map[string]any
	if err := json.Unmarshal(body, &s); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

func apiGet(url, token string) ([]byte, error) { return apiDo(http.MethodGet, url, token, nil) }

func apiDo(method, url, token string, body []byte) ([]byte, error) {
	return apiDoTimeout(method, url, token, body, 10*time.Second)
}

// apiDoTimeout exists because the self-test endpoints deliberately wait: they
// measure how slowly a decoy refuses a password, which is the point.
func apiDoTimeout(method, url, token string, body []byte, timeout time.Duration) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the director at %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned %s: %s", url, resp.Status, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// presenceCA issues the certificates the overlay needs.
//
// It exists because mutual TLS that requires a separate PKI project first is
// mutual TLS nobody turns on, and an unencrypted overlay carries the agent
// token in clear text across someone else's network.
func presenceCA(args []string) error {
	fs := flag.NewFlagSet("presence-ca", flag.ExitOnError)
	dir := fs.String("dir", "presence-pki", "directory to write the material to")
	hosts := fs.String("hosts", "",
		"comma-separated names and addresses agents use to reach the hub (required)")
	agents := fs.String("agents", "", "comma-separated agent ids to issue certificates for (required)")
	days := fs.Int("days", 730, "how long the agent and hub certificates are valid")
	fs.Parse(args)

	if *hosts == "" || *agents == "" {
		return fmt.Errorf("both -hosts and -agents are required; " +
			"the hosts become the hub certificate's SANs and the agents its clients")
	}
	files, err := presence.PKI{
		Dir:      *dir,
		Hosts:    splitList(*hosts),
		Agents:   splitList(*agents),
		Validity: time.Duration(*days) * 24 * time.Hour,
	}.Generate()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ROLE\tKIND\tPATH")
	for _, f := range files {
		fmt.Fprintf(w, "%s\t%s\t%s\n", f.Role, f.Kind, f.Path)
	}
	w.Flush()

	fmt.Printf(`
Hub configuration:

  presence:
    tls:
      cert_file: %s
      key_file: %s
      ca_file: %s

Each agent gets ca.crt and its own pair, and nothing else. ca.key never leaves
this machine: whoever holds it can mint an agent the hub will trust.
`,
		filepath.Join(*dir, "hub.crt"),
		filepath.Join(*dir, "hub.key"),
		filepath.Join(*dir, "ca.crt"))
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// vmsCmd is the operator's handle on full-OS decoys.
func vmsCmd(args []string) error {
	fs := flag.NewFlagSet("vms", flag.ExitOnError)
	addr := fs.String("api", "http://127.0.0.1:8422", "director API base URL")
	token := fs.String("token", "", "bearer token, if the API requires one")
	burn := fs.String("burn", "",
		"take this decoy out of service and preserve it as evidence; it is never restarted")
	revert := fs.String("revert", "",
		"reset this decoy to its baseline; the attacker's state is snapshotted first")
	reason := fs.String("reason", "", "why (recorded in the evidence chain)")
	fs.Parse(args)

	switch {
	case *burn != "" && *revert != "":
		return fmt.Errorf("-burn and -revert are opposites; pick one")
	case *burn != "":
		return vmAction(*addr, *token, *burn, "burn", *reason)
	case *revert != "":
		return vmAction(*addr, *token, *revert, "revert", *reason)
	}

	body, err := apiGet(*addr+"/api/vms", *token)
	if err != nil {
		return err
	}
	var resp struct {
		Enabled   bool `json:"enabled"`
		CanRevert bool `json:"can_revert"`
		Decoys    []struct {
			ID         string    `json:"id"`
			Persona    string    `json:"persona"`
			Template   string    `json:"template"`
			State      string    `json:"state"`
			IPs        []string  `json:"ips"`
			Baseline   bool      `json:"baseline"`
			Burned     bool      `json:"burned"`
			BurnReason string    `json:"burn_reason"`
			Revert     string    `json:"revert"`
			LastRevert time.Time `json:"last_revert"`
		} `json:"decoys"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}
	if !resp.Enabled {
		fmt.Println("This deployment has no full-OS decoys.")
		fmt.Println("They are declared under `vms:` and need a compute driver that can run them")
		fmt.Println("(libvirt or podman) plus a fabric driver to verify containment.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tPERSONA\tSTATE\tBASELINE\tRESET\tADDRESSES\tNOTE")
	for _, d := range resp.Decoys {
		note := ""
		if d.Burned {
			note = "BURNED: " + d.BurnReason
		} else if !d.Baseline {
			note = "no baseline; cannot be reset"
		} else if !d.LastRevert.IsZero() {
			note = "last reset " + d.LastRevert.Format(time.RFC3339)
		}
		reset := d.Revert
		if reset == "" {
			reset = "never"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\t%s\t%s\n",
			d.ID, d.Persona, d.State, d.Baseline, reset, strings.Join(d.IPs, ","), note)
	}
	w.Flush()

	if !resp.CanRevert {
		fmt.Println("\nThis compute driver cannot snapshot, so no decoy here can be reset.")
	}
	return nil
}

func vmAction(addr, token, id, action, reason string) error {
	payload, _ := json.Marshal(map[string]string{"reason": reason})
	body, err := apiDo(http.MethodPost,
		fmt.Sprintf("%s/api/vms/%s/%s", addr, url.PathEscape(id), action), token, payload)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", action, strings.TrimSpace(string(body)))
	if action == "burn" {
		fmt.Println("The decoy is stopped, isolated where the fabric driver can, and kept as it is.")
		fmt.Println("It will not be restarted or reset: it is the forensic artefact now.")
	}
	return nil
}

// checkVMFarm verifies everything a full-OS decoy depends on, and reports the
// live containment verdict rather than the configured intention.
func checkVMFarm(reg *drivers.Registry, cfg *config.Config) int {
	problems := 0
	ctx := context.Background()

	name := cfg.Drivers.Compute
	if name == "" {
		name = "inproc"
	}
	info, ok := reg.Info(drivers.KindCompute, name)
	if !ok {
		fmt.Printf("  [FAIL] full-OS decoys: unknown compute driver %q\n", name)
		return problems + 1
	}
	if !info.Has(drivers.CapFullOS) {
		fmt.Printf("  [warn] %d full-OS decoy(s) declared, but the %q compute driver does not "+
			"run full operating systems\n", len(cfg.VMs.Decoys), name)
		problems++
	}
	compute, err := reg.Compute(name, cfg.Drivers.ComputeConfig)
	if err != nil {
		fmt.Printf("  [FAIL] compute driver %q: %v\n", name, err)
		return problems + 1
	}
	if err := compute.Probe(ctx); err != nil {
		fmt.Printf("  [FAIL] compute driver %q is not usable here: %v\n", name, err)
		problems++
	} else {
		fmt.Printf("  [ ok ] compute driver %q reachable for %d full-OS decoy(s)\n",
			name, len(cfg.VMs.Decoys))
	}
	if !info.Has(drivers.CapSnapshot) || !info.Has(drivers.CapRevert) {
		for _, d := range cfg.VMs.Decoys {
			if d.Revert == farm.RevertOnEngagementEnd {
				fmt.Printf("  [warn] %q asks to be reset after each engagement, but %q cannot "+
					"snapshot; it will stay as the attacker left it\n", d.ID, name)
				problems++
			}
		}
	}

	if cfg.Drivers.Fabric == "" {
		fmt.Println("  [warn] containment is unenforced by configuration: nothing here can tell " +
			"you whether a decoy can reach production")
		return problems + 1
	}
	fab, err := reg.Fabric(cfg.Drivers.Fabric, cfg.Drivers.FabricConfig)
	if err != nil {
		fmt.Printf("  [FAIL] fabric driver %q: %v\n", cfg.Drivers.Fabric, err)
		return problems + 1
	}
	if err := fab.Probe(ctx); err != nil {
		fmt.Printf("  [FAIL] fabric driver %q is not usable here: %v\n", cfg.Drivers.Fabric, err)
		return problems + 1
	}
	violations, err := fab.AssertContainment(ctx)
	if err != nil {
		fmt.Printf("  [FAIL] containment could not be verified: %v\n", err)
		return problems + 1
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Printf("  [FAIL] containment: %s\n", v)
			problems++
		}
		fmt.Println("         full-OS decoys will refuse to start until this is fixed.")
		return problems
	}
	fmt.Printf("  [ ok ] containment verified by %q\n", cfg.Drivers.Fabric)
	return problems
}

func economicsCmd(args []string) error {
	fs := flag.NewFlagSet("economics", flag.ExitOnError)
	addr := fs.String("api", "http://127.0.0.1:8422", "director API base URL")
	token := fs.String("token", "", "bearer token")
	fs.Parse(args)

	body, err := apiGet(*addr+"/api/economics", *token)
	if err != nil {
		return err
	}
	var e struct {
		TotalEngagements   int      `json:"total_engagements"`
		AttackerHours      float64  `json:"attacker_hours"`
		ConfirmedIncidents int      `json:"confirmed_incidents"`
		FalsePositives     int      `json:"false_positives"`
		AvgTimeToDetect    string   `json:"avg_time_to_detect"`
		AvgRiskScore       int      `json:"avg_risk_score"`
		TopTechniques      []string `json:"top_techniques"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return err
	}

	fmt.Println("MIRAGE Engagement Economics")
	fmt.Println("===========================")
	fmt.Printf("  Total engagements:      %d\n", e.TotalEngagements)
	fmt.Printf("  Attacker hours burned:  %.1f\n", e.AttackerHours)
	fmt.Printf("  Confirmed incidents:    %d\n", e.ConfirmedIncidents)
	fmt.Printf("  False positives:        %d (by construction)\n", e.FalsePositives)
	fmt.Printf("  Avg time to detect:     %s\n", e.AvgTimeToDetect)
	fmt.Printf("  Avg risk score:         %d/100\n", e.AvgRiskScore)
	if len(e.TopTechniques) > 0 {
		fmt.Printf("  Top ATT&CK techniques:  %s\n", strings.Join(e.TopTechniques, ", "))
	}
	if e.TotalEngagements == 0 {
		fmt.Println("\nNo engagements yet. Attack a decoy to generate data.")
	}
	return nil
}
