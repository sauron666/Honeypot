package breadcrumbs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The planter is the only code in MIRAGE that writes to a machine the platform
// does not own, so it is written to be reversible and to never destroy. It
// creates new files, or appends a fenced block to existing ones, and records
// every action in a manifest precise enough to undo exactly what it did and
// nothing else.

// fenceStart and fenceEnd delimit an appended block. Removal deletes the text
// between and including them, so a real file the block was appended to comes
// back byte-for-byte -- provided nobody edited inside the fence, which the
// removal checks.
const (
	fenceStart = "# --- mirage-breadcrumb %s (do not edit) ---"
	fenceEnd   = "# --- end mirage-breadcrumb %s ---"
)

// Placed records one crumb that was written, enough to reverse it.
type Placed struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	TokenID string `json:"token_id"`
	Decoy   string `json:"decoy"`
	// Created is true if the planter created the file; false if it appended to
	// a file that already existed. Removal deletes the former and un-fences the
	// latter.
	Created bool `json:"created"`
	// Fence is the id used in the block delimiters, for an appended crumb.
	Fence string `json:"fence,omitempty"`
}

// Manifest is the record of one planting run, written to disk so a later
// removal -- possibly by a different invocation -- can reverse it exactly.
type Manifest struct {
	Host      string    `json:"host"`
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	Placed    []Placed  `json:"placed"`
}

// Planter writes crumbs to disk under a root, and reverses them.
type Planter struct {
	// root is prepended to every crumb path. In production it is "/" (or the
	// drive), so crumb paths are absolute; in tests it is a temp dir, so the
	// same code writes into a sandbox without touching the real home.
	root string
	now  func() time.Time
}

// NewPlanter builds a planter rooted at root. A root of "" means the filesystem
// root, i.e. crumb paths are used as-is.
func NewPlanter(root string) *Planter {
	return &Planter{root: root, now: time.Now}
}

func (pl *Planter) resolve(p string) string {
	if pl.root == "" {
		return p
	}
	// Crumb paths may be Windows-style in a cross-rendered plan; normalise the
	// separators so a test on Linux can host a Windows crumb under its root.
	clean := strings.ReplaceAll(p, `\`, "/")
	clean = strings.TrimPrefix(clean, "/")
	// Drive letters (C:) become a directory under the root, so nothing escapes.
	clean = strings.Replace(clean, ":", "", 1)
	return filepath.Join(pl.root, filepath.FromSlash(clean))
}

// Place writes one crumb and returns how it was recorded. It never overwrites
// or truncates: a new file is created with O_EXCL, and an existing file is only
// appended to. A crumb that is not marked Append but whose file already exists
// is refused, because silently overwriting a real file the user happened to
// have is exactly the harm this package must not do.
func (pl *Planter) Place(c Crumb) (Placed, error) {
	full := pl.resolve(c.Path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return Placed{}, err
	}
	mode := parseMode(c.Mode)

	if !c.Append {
		f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return Placed{}, fmt.Errorf("breadcrumbs: %s already exists; refusing to overwrite it "+
					"(a breadcrumb never destroys a real file)", full)
			}
			return Placed{}, err
		}
		defer f.Close()
		if _, err := f.WriteString(c.Content); err != nil {
			return Placed{}, err
		}
		return Placed{Kind: c.Kind, Path: c.Path, TokenID: c.TokenID, Decoy: c.Decoy, Created: true}, nil
	}

	// Append path: fence the block so removal can find and excise it exactly.
	existed := fileExists(full)
	fence := c.TokenID
	block := fmt.Sprintf(fenceStart+"\n%s"+fenceEnd+"\n", fence, ensureTrailingNewline(c.Content), fence)

	f, err := os.OpenFile(full, os.O_CREATE|os.O_APPEND|os.O_WRONLY, mode)
	if err != nil {
		return Placed{}, err
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return Placed{}, err
	}
	return Placed{
		Kind: c.Kind, Path: c.Path, TokenID: c.TokenID, Decoy: c.Decoy,
		Created: !existed, Fence: fence,
	}, nil
}

// PlaceAll writes every crumb and returns a manifest. If any crumb fails, the
// ones already placed are rolled back, so a partial run does not leave a mess
// on someone's machine with no record of it.
func (pl *Planter) PlaceAll(crumbs []Crumb, host, user string) (*Manifest, error) {
	m := &Manifest{Host: host, User: user, CreatedAt: pl.now()}
	for _, c := range crumbs {
		placed, err := pl.Place(c)
		if err != nil {
			// Roll back what we managed to place, so failure leaves nothing.
			_ = pl.Remove(m)
			return nil, err
		}
		m.Placed = append(m.Placed, placed)
	}
	return m, nil
}

// Remove reverses a manifest: created files are deleted, appended blocks are
// excised. A block someone edited inside the fence is left in place and
// reported, because deleting text a human has changed would be the same kind of
// destruction the planter refuses on the way in.
func (pl *Planter) Remove(m *Manifest) error {
	var problems []string
	// Reverse order, so a file that was created and later appended to unwinds
	// cleanly.
	for i := len(m.Placed) - 1; i >= 0; i-- {
		p := m.Placed[i]
		full := pl.resolve(p.Path)
		if p.Created {
			if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
				problems = append(problems, fmt.Sprintf("%s: %v", full, err))
			}
			continue
		}
		if err := pl.unfence(full, p.Fence); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", full, err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("breadcrumbs: removal left %d item(s) needing a look: %s",
			len(problems), strings.Join(problems, "; "))
	}
	return nil
}

// unfence removes exactly the fenced block with the given id from a file. The
// rest of the file -- a real ~/.ssh/config, say -- is preserved.
func (pl *Planter) unfence(path, fence string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	start := fmt.Sprintf(fenceStart, fence)
	end := fmt.Sprintf(fenceEnd, fence)
	lines := strings.Split(string(data), "\n")
	var out []string
	inBlock := false
	found := false
	for _, l := range lines {
		switch {
		case strings.TrimSpace(l) == start:
			inBlock = true
			found = true
		case strings.TrimSpace(l) == end:
			inBlock = false
		case !inBlock:
			out = append(out, l)
		}
	}
	if !found {
		return nil // already gone; not an error
	}
	result := strings.Join(out, "\n")
	// If nothing but our block was in the file, remove it entirely rather than
	// leaving an empty file the user never had.
	if strings.TrimSpace(result) == "" {
		return os.Remove(path)
	}
	return os.WriteFile(path, []byte(result), 0o600)
}

// SaveManifest writes a manifest to disk so a later removal can find it.
func SaveManifest(m *Manifest, path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadManifest reads a manifest written by SaveManifest.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("breadcrumbs: %s is not a manifest: %w", path, err)
	}
	return &m, nil
}

func parseMode(s string) os.FileMode {
	if s == "" {
		return 0o600
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0o600
	}
	return os.FileMode(n)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
