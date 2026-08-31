package catalog

import (
	"fmt"
	"strings"
)

// Sanitisation turns a third-party or CTF image into a safe decoy. Three things
// must happen before an image an operator did not build becomes a live decoy:
//
//  1. CTF flags are removed — a decoy that still contains user.txt/root.txt
//     tells a knowledgeable attacker exactly what it is.
//  2. Known/default credentials are reset — a HackTheBox box ships with its
//     intended foothold creds; left in place they are a giveaway and a risk.
//  3. A tracking watermark is embedded — so leaked decoy content is traceable
//     back to this deployment (see internal/watermark).
//
// This file plans those actions declaratively and portably (fully testable).
// Applying them to a real disk image needs guest tooling (libguestfs'
// virt-customize), which is Linux- and host-dependent; the applier lives in
// sanitize_apply.go behind a capability probe, and is honest when the tooling
// is absent.

// ActionKind categorises a sanitisation step.
type ActionKind string

const (
	ActionRemoveFile ActionKind = "remove-file"
	ActionResetCred  ActionKind = "reset-credential"
	ActionEmbedMark  ActionKind = "embed-watermark"
	ActionRunCommand ActionKind = "run-command"
)

// Action is one sanitisation step, both human-readable and machine-applicable.
type Action struct {
	Kind   ActionKind `json:"kind"`
	Target string     `json:"target"`           // path, account, or command
	Detail string     `json:"detail,omitempty"` // why / what value
}

// Ruleset describes what to strip and reset. Deployments can extend it, but the
// defaults cover the common CTF layouts.
type Ruleset struct {
	// FlagPaths are files to delete outright (globs allowed by the applier).
	FlagPaths []string
	// ResetAccounts get a fresh random password (the operator keeps the map the
	// applier returns; here we only plan the reset).
	ResetAccounts []string
	// Watermark, when set, is embedded into a marker file for leak tracing.
	Watermark string
	// ExtraCommands run inside the guest after the above (e.g. clear bash
	// history, remove SSH authorized_keys). Each is a shell command.
	ExtraCommands []string
}

// DefaultCTFRuleset returns the flag locations and hygiene steps that cover
// HackTheBox, VulnHub and most CTF images. It is deliberately broad: a leftover
// flag is a worse failure than an over-eager delete on a throwaway decoy image.
func DefaultCTFRuleset(watermark string) Ruleset {
	return Ruleset{
		FlagPaths: []string{
			"/root/root.txt",
			"/root/flag.txt",
			"/root/flag",
			"/root/proof.txt",
			"/home/*/user.txt",
			"/home/*/local.txt",
			"/home/*/flag.txt",
			"/flag",
			"/flag.txt",
			"/var/www/flag*",
			"/tmp/flag*",
			"C:/Users/*/Desktop/root.txt",
			"C:/Users/*/Desktop/user.txt",
			"C:/flag.txt",
		},
		ResetAccounts: []string{"root", "administrator"},
		Watermark:     watermark,
		ExtraCommands: []string{
			"rm -f /root/.bash_history /home/*/.bash_history",
			"rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys",
			"rm -f /root/.msf4/history",
		},
	}
}

// Plan turns a ruleset into an ordered list of actions for a given image. It is
// pure: it inspects nothing on disk, so it is safe to show as a preview and to
// unit-test. The applier is what actually touches the image.
func (im *Image) Plan(rs Ruleset) []Action {
	var actions []Action
	for _, p := range rs.FlagPaths {
		actions = append(actions, Action{
			Kind: ActionRemoveFile, Target: p,
			Detail: "remove CTF flag / proof file so the decoy does not advertise its origin",
		})
	}
	for _, acct := range rs.ResetAccounts {
		actions = append(actions, Action{
			Kind: ActionResetCred, Target: acct,
			Detail: "reset to a fresh random password; the known foothold credential is a tell and a risk",
		})
	}
	if rs.Watermark != "" {
		actions = append(actions, Action{
			Kind: ActionEmbedMark, Target: "/etc/.mirage-mark",
			Detail: "embed a per-deployment watermark for leak tracing: " + rs.Watermark,
		})
	}
	for _, cmd := range rs.ExtraCommands {
		actions = append(actions, Action{
			Kind: ActionRunCommand, Target: cmd,
			Detail: "hygiene: clear history / keys left by the image author",
		})
	}
	return actions
}

// PlanReport renders a plan as a readable checklist.
func PlanReport(im *Image, actions []Action) string {
	var b strings.Builder
	fmt.Fprintf(&b, "sanitisation plan for %q (%s, %s)\n", im.Name, im.ID, im.Difficulty)
	fmt.Fprintf(&b, "image: %s [%s]\n\n", im.Path, im.Format)
	if len(actions) == 0 {
		b.WriteString("  (no actions)\n")
		return b.String()
	}
	for i, a := range actions {
		fmt.Fprintf(&b, "  %2d. [%s] %s\n", i+1, a.Kind, a.Target)
		if a.Detail != "" {
			fmt.Fprintf(&b, "      %s\n", a.Detail)
		}
	}
	fmt.Fprintf(&b, "\n%d actions. Nothing is changed until you apply the plan.\n", len(actions))
	return b.String()
}
