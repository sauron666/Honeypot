// Command miragectl is the MIRAGE command-line tool: configuration checks,
// offline evidence verification and queries against a running director.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/driverset"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/honeyd"
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
		"modbus":  "Modbus/TCP PLC; reads are recon, writes are treated as process manipulation",
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

func apiGet(url, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the director at %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
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
