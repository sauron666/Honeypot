package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/catalog"
)

// imagesCmd is the operator-facing image library: import a decoy image, tag it
// by difficulty, list/retag/remove, and sanitise it (strip CTF flags, reset
// known credentials, embed a watermark) before it goes live.
func imagesCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: miragectl images list|import|retag|remove|sanitize [flags]")
	}
	switch args[0] {
	case "list":
		return imagesList(args[1:])
	case "import":
		return imagesImport(args[1:])
	case "retag":
		return imagesRetag(args[1:])
	case "remove":
		return imagesRemove(args[1:])
	case "sanitize", "sanitise":
		return imagesSanitize(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q (list | import | retag | remove | sanitize)", args[0])
	}
}

func openCatalog(path string) (*catalog.Catalog, error) {
	return catalog.Open(path)
}

func imagesList(args []string) error {
	fs := flag.NewFlagSet("images list", flag.ExitOnError)
	path := fs.String("catalog", "data/images.json", "image catalog file")
	diff := fs.String("difficulty", "", "filter: easy|medium|hard|insane")
	sanitized := fs.Bool("sanitized", false, "only images cleared for deployment")
	fs.Parse(args)

	cat, err := openCatalog(*path)
	if err != nil {
		return err
	}
	imgs := cat.List(catalog.Filter{
		Difficulty:    catalog.Difficulty(*diff),
		SanitizedOnly: *sanitized,
	})
	if len(imgs) == 0 {
		fmt.Println("no images in the catalog")
		return nil
	}
	fmt.Printf("%-24s %-8s %-8s %-12s %-9s %s\n", "ID", "DIFF", "FORMAT", "PERSONA", "SANITISED", "PATH")
	for _, im := range imgs {
		san := "no"
		if im.Sanitized {
			san = "yes"
		}
		fmt.Printf("%-24s %-8s %-8s %-12s %-9s %s\n",
			im.ID, im.Difficulty, im.Format, im.Persona, san, im.Path)
	}
	return nil
}

func imagesImport(args []string) error {
	fs := flag.NewFlagSet("images import", flag.ExitOnError)
	path := fs.String("catalog", "data/images.json", "image catalog file")
	file := fs.String("file", "", "path to the image (iso/ova/ovf/qcow2/vmdk/raw) (required)")
	name := fs.String("name", "", "display name (default: filename)")
	diff := fs.String("difficulty", "medium", "easy|medium|hard|insane")
	persona := fs.String("persona", "", "what the image portrays, e.g. linux/web")
	source := fs.String("source", "custom", "provenance: htb|vulnhub|custom|<vendor>")
	tags := fs.String("tags", "", "comma-separated tags")
	sum := fs.Bool("checksum", true, "compute a SHA-256 (pins the bytes; slow on huge images)")
	fs.Parse(args)

	if *file == "" {
		return fmt.Errorf("--file is required")
	}
	cat, err := openCatalog(*path)
	if err != nil {
		return err
	}
	im, err := cat.Import(*file, catalog.ImportOptions{
		Name:       *name,
		Difficulty: catalog.Difficulty(*diff),
		Persona:    *persona,
		Source:     *source,
		Tags:       splitTags(*tags),
		Checksum:   *sum,
	})
	if err != nil {
		return err
	}
	fmt.Printf("imported %q as %s (%s, %s)\n", im.Name, im.ID, im.Difficulty, im.Format)
	fmt.Printf("  NOT yet sanitised — run: miragectl images sanitize --id %s\n", im.ID)
	return nil
}

func imagesRetag(args []string) error {
	fs := flag.NewFlagSet("images retag", flag.ExitOnError)
	path := fs.String("catalog", "data/images.json", "image catalog file")
	id := fs.String("id", "", "image id (required)")
	diff := fs.String("difficulty", "", "new difficulty (leave empty to keep)")
	tags := fs.String("tags", "", "replace tags with this comma-separated list")
	fs.Parse(args)

	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	cat, err := openCatalog(*path)
	if err != nil {
		return err
	}
	var newTags []string
	if *tags != "" {
		newTags = splitTags(*tags)
	}
	if err := cat.Retag(*id, catalog.Difficulty(*diff), newTags); err != nil {
		return err
	}
	fmt.Printf("retagged %s\n", *id)
	return nil
}

func imagesRemove(args []string) error {
	fs := flag.NewFlagSet("images remove", flag.ExitOnError)
	path := fs.String("catalog", "data/images.json", "image catalog file")
	id := fs.String("id", "", "image id (required)")
	fs.Parse(args)

	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	cat, err := openCatalog(*path)
	if err != nil {
		return err
	}
	if err := cat.Remove(*id); err != nil {
		return err
	}
	fmt.Printf("removed %s from the catalog (the image file is left on disk)\n", *id)
	return nil
}

func imagesSanitize(args []string) error {
	fs := flag.NewFlagSet("images sanitize", flag.ExitOnError)
	path := fs.String("catalog", "data/images.json", "image catalog file")
	id := fs.String("id", "", "image id (required)")
	watermark := fs.String("watermark", "", "watermark to embed (default: the image id)")
	apply := fs.Bool("apply", false, "actually apply (needs virt-customize); default is a dry-run plan")
	fs.Parse(args)

	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	cat, err := openCatalog(*path)
	if err != nil {
		return err
	}
	im, ok := cat.Get(*id)
	if !ok {
		return fmt.Errorf("no image %q", *id)
	}
	wm := *watermark
	if wm == "" {
		wm = im.ID
	}
	plan := im.Plan(catalog.DefaultCTFRuleset(wm))
	fmt.Print(catalog.PlanReport(im, plan))

	if !*apply {
		fmt.Printf("\ndry-run. Re-run with --apply to execute (auto-apply %s).\n",
			toolState())
		return nil
	}

	res, err := catalog.Apply(context.Background(), im.Path, plan)
	if err != nil {
		// Print what would have run so the operator can act manually.
		fmt.Printf("\ncould not auto-apply: %v\n", err)
		fmt.Printf("command that would run:\n  %s %s\n", res.Tool, strings.Join(res.Args, " "))
		return err
	}
	if len(res.Passwords) > 0 {
		fmt.Println("\nreset credentials (record these):")
		for acct, pw := range res.Passwords {
			fmt.Printf("  %s: %s\n", acct, pw)
		}
	}
	if err := cat.MarkSanitized(im.ID, time.Now()); err != nil {
		return err
	}
	fmt.Printf("\nsanitised and marked deployable: %s\n", im.ID)
	return nil
}

func toolState() string {
	if catalog.ToolAvailable() {
		return "available: virt-customize found"
	}
	return "unavailable: install libguestfs-tools for auto-apply"
}

func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
