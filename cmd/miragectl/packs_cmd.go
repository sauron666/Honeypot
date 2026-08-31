package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sauron666/Honeypot/internal/honeyd"
	"github.com/sauron666/Honeypot/internal/packs"
	"github.com/sauron666/Honeypot/internal/vault"
	"gopkg.in/yaml.v3"
)

// packsCmd is the Deception Pack tool: list the catalogue, inspect a pack,
// sign/verify one, and print the config fragment to merge into a profile.
func packsCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: miragectl packs list|show|apply|sign|verify [flags]")
	}
	switch args[0] {
	case "list":
		return packsList(args[1:])
	case "show":
		return packsShow(args[1:])
	case "apply":
		return packsApply(args[1:])
	case "sign":
		return packsSign(args[1:])
	case "verify":
		return packsVerify(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q (list | show | apply | sign | verify)", args[0])
	}
}

func personaChecker(name string) bool {
	for _, n := range honeyd.PersonaNames() {
		if n == name {
			return true
		}
	}
	return false
}

// resolvePack loads a pack by built-in name or file path.
func resolvePack(ref string) (*packs.Pack, error) {
	if p, ok := packs.BuiltinByName(ref); ok {
		return p, nil
	}
	if _, err := os.Stat(ref); err == nil {
		return packs.Load(ref)
	}
	return nil, fmt.Errorf("no built-in pack %q and no file at that path", ref)
}

func packsList(args []string) error {
	all, err := packs.Builtin()
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-8s %-12s %-8s %s\n", "NAME", "VERSION", "VERTICAL", "LOCALE", "CONTENT")
	for _, p := range all {
		valid := "ok"
		if err := p.Validate(personaChecker); err != nil {
			valid = "INVALID"
		}
		fmt.Printf("%-16s %-8s %-12s %-8s %d decoys, %d tokens  [%s]\n",
			p.Name, p.Version, p.Vertical, p.Locale, len(p.Decoys), len(p.Honeytokens), valid)
	}
	fmt.Println("\nshow one:  miragectl packs show <name|file>")
	return nil
}

func packsShow(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: miragectl packs show <name|file>")
	}
	p, err := resolvePack(args[0])
	if err != nil {
		return err
	}
	fmt.Print(p.Summary())
	if err := p.Validate(personaChecker); err != nil {
		fmt.Printf("\nWARNING: %v\n", err)
	}
	return nil
}

// packsApply prints the profile fragment (decoys) and the honeytokens to mint,
// so an operator merges the decoys into their manifest and mints the tokens.
// It does not mutate a running deployment: applying deception content is an
// explicit, reviewable act.
func packsApply(args []string) error {
	fs := flag.NewFlagSet("packs apply", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: miragectl packs apply <name|file>")
	}
	p, err := resolvePack(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := p.Validate(personaChecker); err != nil {
		return err
	}

	// Emit the decoys as a YAML fragment ready to paste under `honeyd.decoys`.
	frag := map[string]any{"decoys": p.Decoys}
	out, err := yaml.Marshal(frag)
	if err != nil {
		return err
	}
	fmt.Printf("# --- paste under honeyd.decoys in your profile (pack %s v%s) ---\n", p.Name, p.Version)
	fmt.Print(string(out))

	if len(p.Honeytokens) > 0 {
		fmt.Printf("\n# --- mint these honeytokens against a running director ---\n")
		for _, t := range p.Honeytokens {
			fmt.Printf("miragectl tokens -mint %s -label %q -location %q\n", t.Type, t.Label, t.Location)
		}
	}
	if len(p.Lures) > 0 {
		fmt.Printf("\n# --- suggested breadcrumbs (see mirage-breadcrumbs) ---\n")
		for _, l := range p.Lures {
			fmt.Printf("#   %s -> %s   %s\n", l.Kind, l.Target, l.Note)
		}
	}
	return nil
}

func packsSign(args []string) error {
	fs := flag.NewFlagSet("packs sign", flag.ExitOnError)
	packFile := fs.String("pack", "", "pack file to sign (required)")
	keyPath := fs.String("key", "data/vault.key", "signing key (the deployment's vault key; created if absent)")
	out := fs.String("out", "", "write the signed pack here (default: overwrite --pack)")
	fs.Parse(args)
	if *packFile == "" {
		return fmt.Errorf("--pack is required")
	}
	p, err := packs.Load(*packFile)
	if err != nil {
		return err
	}
	kp, err := vault.LoadKey(*keyPath)
	if err != nil {
		kp, err = vault.GenerateKeypair()
		if err != nil {
			return err
		}
		if err := kp.SaveKey(*keyPath); err != nil {
			return err
		}
		fmt.Printf("created a new signing key: %s\n", *keyPath)
	}
	fp := vault.Fingerprint(kp.Public)
	if err := p.Sign(kp.Private, fp); err != nil {
		return err
	}
	raw, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	dst := *out
	if dst == "" {
		dst = *packFile
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s by %s -> %s\n", p.Name, fp, dst)
	return nil
}

func packsVerify(args []string) error {
	fs := flag.NewFlagSet("packs verify", flag.ExitOnError)
	packFile := fs.String("pack", "", "pack file to verify (required)")
	keyPath := fs.String("key", "data/vault.key", "the vault key whose public half signed the pack")
	fs.Parse(args)
	if *packFile == "" {
		return fmt.Errorf("--pack is required")
	}
	p, err := packs.Load(*packFile)
	if err != nil {
		return err
	}
	kp, err := vault.LoadKey(*keyPath)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	if err := p.Verify(kp.Public); err != nil {
		fmt.Printf("VERIFY FAILED: %v\n", err)
		return err
	}
	fmt.Printf("VERIFIED: %s v%s signed by %s\n", p.Name, p.Version, vault.Fingerprint(kp.Public))
	return nil
}
