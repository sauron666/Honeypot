package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/analyst"
	"github.com/sauron666/Honeypot/internal/bec"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/feed"
	"github.com/sauron666/Honeypot/internal/saasid"
	"github.com/sauron666/Honeypot/internal/store"
	"github.com/sauron666/Honeypot/internal/vault"
	"github.com/sauron666/Honeypot/internal/wireless"
)

// loadEngagements reconstructs engagements from an evidence file, sorted by risk.
func loadEngagements(path string) ([]*engagement.Engagement, error) {
	st, err := store.OpenFile(path, store.FileOptions{MemoryWindow: 500_000})
	if err != nil {
		return nil, err
	}
	defer st.Close()
	all, err := st.Query(context.Background(), store.Query{Limit: 1_000_000, Ascending: true})
	if err != nil {
		return nil, err
	}
	engs := engagement.FromEvents(all)
	if len(engs) == 0 {
		return nil, fmt.Errorf("no engagements in %s", path)
	}
	return engs, nil
}

// --- idea 11: SaaS / identity deception ---

func saasidCmd(args []string) error {
	fs := flag.NewFlagSet("saasid", flag.ExitOnError)
	provider := fs.String("provider", "entra", "entra | okta | workspace")
	domain := fs.String("domain", "corp.local", "the tenant domain the honey identities live in")
	fs.Parse(args)

	k := saasid.Generate(saasid.Provider(*provider), *domain)
	fmt.Printf("Honey identities for %s (%s)\n\n", k.Domain, k.Provider)
	fmt.Println("ACCOUNTS (login-less — any sign-in is an attack):")
	for _, a := range k.Accounts {
		fmt.Printf("  %-28s %-22s %s\n", a.UPN, a.Role, a.Note)
	}
	fmt.Printf("\nHONEY OAUTH APP (consent-phishing bait):\n  %s  client_id=%s\n  scopes: %s\n",
		k.OAuthApp.Name, k.OAuthApp.ClientID, strings.Join(k.OAuthApp.Scopes, ", "))
	fmt.Printf("\nHONEY DOCS/CHANNELS: %s | %s\n", strings.Join(k.Documents, ", "), strings.Join(k.Channels, ", "))
	fmt.Printf("\n%s\n", k.CAPolicy)
	fmt.Printf("\nWATCH THESE in the provider audit log (any hit = alert):\n  %s\n",
		strings.Join(k.WatchList(), "\n  "))
	return nil
}

// --- idea 12: email / BEC deception ---

func becCmd(args []string) error {
	if len(args) > 0 && args[0] == "analyze" {
		return becAnalyze(args[1:])
	}
	fs := flag.NewFlagSet("bec", flag.ExitOnError)
	domain := fs.String("domain", "corp.local", "the domain the honey finance identities live in")
	fs.Parse(args)

	k := bec.Generate(*domain)
	fmt.Printf("Honey finance identities for %s (put these on the public site):\n\n", k.Domain)
	for _, p := range k.Personas {
		fmt.Printf("  %-20s %-18s %s\n", p.Name, p.Role, p.Email)
	}
	fmt.Println("\nHoney mailboxes (leak into public corpora):")
	for _, m := range k.Mailboxes {
		fmt.Printf("  %-24s  seeded in: %s\n", m.Address, m.SeededIn)
	}
	fmt.Printf("\nWatch as recipients on the mail gateway:\n  %s\n", strings.Join(k.WatchAddresses(), "\n  "))
	fmt.Println("\nAnalyse a received message: miragectl bec analyze < message.eml")
	return nil
}

func becAnalyze(args []string) error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8*1024*1024))
	if err != nil {
		return err
	}
	c, err := bec.AnalyzeEmail(string(raw))
	if err != nil {
		return err
	}
	fmt.Printf("Subject:     %s\n", c.Subject)
	fmt.Printf("From:        %q <%s>\n", c.FromName, c.FromAddress)
	if c.ReplyTo != "" {
		fmt.Printf("Reply-To:    %s\n", c.ReplyTo)
	}
	if c.ReturnPath != "" {
		fmt.Printf("Return-Path: %s\n", c.ReturnPath)
	}
	if len(c.SenderIPs) > 0 {
		fmt.Printf("Sender IPs:  %s\n", strings.Join(c.SenderIPs, ", "))
	}
	if len(c.URLs) > 0 {
		fmt.Printf("URLs:        %s\n", strings.Join(c.URLs, ", "))
	}
	fmt.Printf("Reply mismatch: %v\n", c.ReplyMismatch)
	if c.IsBEC {
		fmt.Println("\nVERDICT: likely BEC (spoofed sender / external reply). Push the IOCs above to the mail gateway.")
	} else {
		fmt.Println("\nVERDICT: no BEC tell detected.")
	}
	return nil
}

// --- idea 18: local LLM analyst ---

func analystCmd(args []string) error {
	fs := flag.NewFlagSet("analyst", flag.ExitOnError)
	path := fs.String("file", "data/evidence.jsonl", "evidence file")
	engID := fs.String("engagement", "", "engagement id (default: the highest-risk one)")
	endpoint := fs.String("endpoint", "", "OpenAI-compatible local endpoint (e.g. http://localhost:11434/v1); empty = offline template")
	model := fs.String("model", "llama3", "model name for the LLM endpoint")
	key := fs.String("key", "", "API key for the endpoint, if it needs one")
	fs.Parse(args)

	engs, err := loadEngagements(*path)
	if err != nil {
		return err
	}
	eng := engs[0]
	if *engID != "" {
		eng = nil
		for _, e := range engs {
			if e.ID == *engID {
				eng = e
			}
		}
		if eng == nil {
			return fmt.Errorf("no engagement %q in %s", *engID, *path)
		}
	}

	var a analyst.Analyst = analyst.Template{}
	if *endpoint != "" {
		a = analyst.NewLLM(*endpoint, *model, *key)
	}
	n, err := a.Analyze(context.Background(), *eng)
	if err != nil {
		// The analyst is never in the critical path: fall back to the offline
		// template rather than failing.
		fmt.Fprintf(os.Stderr, "analyst: LLM endpoint failed (%v); using the offline template\n", err)
		n, _ = analyst.Template{}.Analyze(context.Background(), *eng)
	}
	fmt.Printf("# Analyst narrative (source: %s)\n\n%s\n\n## Suggested Sigma (draft)\n%s\n",
		n.Source, n.ReportDraft, n.SuggestedSigma)
	if n.RequiresReview {
		fmt.Println("\n>>> REQUIRES HUMAN REVIEW — not an automated verdict, never used for alerting.")
	}
	return nil
}

// --- idea 19: global feed (opt-in, anonymized) ---

func feedCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: miragectl feed export|import [flags]")
	}
	switch args[0] {
	case "export":
		return feedExport(args[1:])
	case "import":
		return feedImport(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q (export | import)", args[0])
	}
}

func feedExport(args []string) error {
	fs := flag.NewFlagSet("feed export", flag.ExitOnError)
	path := fs.String("file", "data/evidence.jsonl", "evidence file")
	salt := fs.String("salt", "", "per-deployment salt (stable; identifies your feed without naming you) (required)")
	keyPath := fs.String("key", "data/vault.key", "vault key to sign the feed (created if absent)")
	out := fs.String("out", "", "write the feed here (default: stdout)")
	fs.Parse(args)
	if *salt == "" {
		return fmt.Errorf("--salt is required (any stable secret string for your deployment)")
	}

	engs, err := loadEngagements(*path)
	if err != nil {
		return err
	}
	f := &feed.Feed{Version: 1, GeneratedAt: time.Now()}
	for _, e := range engs {
		f.Entries = append(f.Entries, feed.Anonymize(*e, *salt))
	}
	kp, err := vault.LoadKey(*keyPath)
	if err != nil {
		if kp, err = vault.GenerateKeypair(); err != nil {
			return err
		}
		if err := kp.SaveKey(*keyPath); err != nil {
			return err
		}
	}
	if err := f.Sign(kp.Private, vault.Fingerprint(kp.Public)); err != nil {
		return err
	}
	raw, err := f.Marshal()
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(string(raw))
		fmt.Fprintf(os.Stderr, "\n%d anonymized entries, signed by %s. NO IPs/tenant/tokens are included.\n",
			len(f.Entries), vault.Fingerprint(kp.Public))
		return nil
	}
	return os.WriteFile(*out, raw, 0o644)
}

func feedImport(args []string) error {
	fs := flag.NewFlagSet("feed import", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: miragectl feed import <feed1.json> [feed2.json ...]")
	}
	merged := &feed.Feed{Version: 1, GeneratedAt: time.Now()}
	for _, p := range fs.Args() {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := feed.ParseFeed(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		merged.Merge(f)
	}
	fmt.Printf("merged %d entries from %d feed(s)\n", len(merged.Entries), fs.NArg())
	techniques := map[string]int{}
	for _, e := range merged.Entries {
		for _, tq := range e.Techniques {
			techniques[tq]++
		}
	}
	fmt.Println("technique frequency across the feed:")
	for tq, n := range techniques {
		fmt.Printf("  %-14s %d\n", tq, n)
	}
	return nil
}

// --- idea 20: wireless / BYOD deception (IP-discovery slice) ---

func wirelessCmd(args []string) error {
	devs := wireless.DefaultHoneyDevices()
	fmt.Println("Honey network-discoverable devices (advertise over mDNS/DNS-SD):")
	for _, d := range devs {
		fmt.Printf("  %-18s %-18s %s:%d  [%s]\n", d.Instance, d.ServiceType, d.Host, d.Port, d.Kind)
	}
	fmt.Println("\nBrowse names to watch (a query for one of these = BYOD/rogue recon):")
	for _, n := range wireless.BrowseNames(devs) {
		fmt.Printf("  %s\n", n)
	}
	fmt.Printf("\nScope: %s\n", wireless.LiveAdvertising())
	return nil
}
