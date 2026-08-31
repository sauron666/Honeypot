package catalog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrToolMissing means the guest-customisation tool is not installed, so the
// plan cannot be applied automatically. The caller still has the plan and can
// apply it by hand; MIRAGE never pretends an image was sanitised when it was
// not.
var ErrToolMissing = errors.New("catalog: virt-customize (libguestfs) not found; " +
	"install libguestfs-tools to apply sanitisation automatically, or apply the plan manually")

// The tool we drive. libguestfs' virt-customize mounts a disk image without
// booting it and applies edits — the safe way to sanitise an offline image.
const customizeTool = "virt-customize"

// ToolAvailable reports whether the guest-customisation tool is on PATH. The UI
// and CLI probe this so they can show honestly whether auto-apply is possible.
func ToolAvailable() bool {
	_, err := exec.LookPath(customizeTool)
	return err == nil
}

// BuildArgs turns a plan into virt-customize arguments for imagePath. It is pure
// and unit-tested; Apply is the thin exec wrapper. It returns the generated
// passwords for reset accounts so the operator can record them.
func BuildArgs(imagePath string, actions []Action) (args []string, passwords map[string]string) {
	args = []string{"-a", imagePath}
	passwords = map[string]string{}
	for _, a := range actions {
		switch a.Kind {
		case ActionRemoveFile:
			args = append(args, "--delete", a.Target)
		case ActionResetCred:
			pw := randomPassword()
			passwords[a.Target] = pw
			args = append(args, "--password", a.Target+":password:"+pw)
		case ActionEmbedMark:
			// --write path:content embeds the watermark marker file.
			mark := strings.TrimPrefix(a.Detail, "embed a per-deployment watermark for leak tracing: ")
			args = append(args, "--write", a.Target+":"+mark)
		case ActionRunCommand:
			args = append(args, "--run-command", a.Target)
		}
	}
	return args, passwords
}

// ApplyResult reports what an apply did.
type ApplyResult struct {
	Applied   bool              `json:"applied"`
	Tool      string            `json:"tool"`
	Args      []string          `json:"args"`
	Passwords map[string]string `json:"passwords,omitempty"`
	Output    string            `json:"output,omitempty"`
}

// Apply runs the sanitisation plan against the image using virt-customize. If
// the tool is missing it returns ErrToolMissing together with the args it would
// have run, so the operator can act. On success it does NOT mark the image
// sanitised in the catalog — the caller does that, so a failed verification can
// withhold the mark.
func Apply(ctx context.Context, imagePath string, actions []Action) (*ApplyResult, error) {
	args, passwords := BuildArgs(imagePath, actions)
	res := &ApplyResult{Tool: customizeTool, Args: args, Passwords: passwords}
	if !ToolAvailable() {
		return res, ErrToolMissing
	}
	cmd := exec.CommandContext(ctx, customizeTool, args...)
	out, err := cmd.CombinedOutput()
	res.Output = string(out)
	if err != nil {
		return res, fmt.Errorf("catalog: virt-customize failed: %w", err)
	}
	res.Applied = true
	return res, nil
}

func randomPassword() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "change-me-" + hex.EncodeToString([]byte("fallback"))
	}
	return hex.EncodeToString(b[:])
}
