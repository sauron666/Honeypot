package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAccidentalPlatformConstraints guards against a filename silently
// removing code from the build.
//
// Go treats a _windows, _linux, _darwin or _amd64 suffix on a file name as a
// build constraint. A persona file called persona_windows.go compiles only on
// Windows, so the decoy it defines simply does not exist anywhere else -- and
// nothing fails to build, which is what makes it dangerous.
func TestNoAccidentalPlatformConstraints(t *testing.T) {
	// The suffixes Go interprets. Any file ending in one of these, before .go,
	// is constrained to that platform.
	constrained := map[string]bool{
		"windows": true, "linux": true, "darwin": true, "freebsd": true,
		"openbsd": true, "netbsd": true, "js": true, "wasip1": true, "plan9": true,
		"android": true, "ios": true, "solaris": true, "aix": true, "dragonfly": true,
		"amd64": true, "arm64": true, "386": true, "arm": true, "riscv64": true,
		"ppc64": true, "ppc64le": true, "s390x": true, "mips": true, "mips64": true,
		"loong64": true, "wasm": true,
	}
	// Files that genuinely want the constraint belong here, with a reason.
	allowed := map[string]string{}

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "bin" || name == "data" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		stem := strings.TrimSuffix(name, ".go")
		stem = strings.TrimSuffix(stem, "_test")
		i := strings.LastIndex(stem, "_")
		if i < 0 {
			return nil
		}
		suffix := stem[i+1:]
		if !constrained[suffix] {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if _, ok := allowed[rel]; ok {
			return nil
		}
		t.Errorf("%s is compiled only on %s because of its filename; "+
			"rename it unless that is intended (add it to the allow list if so)", rel, suffix)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
