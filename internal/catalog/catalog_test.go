package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempImage(t *testing.T, name string, size int) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImportRecordsMetadataAndDetectsFormat(t *testing.T) {
	cat, err := Open(filepath.Join(t.TempDir(), "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	img := tempImage(t, "web01.qcow2", 4096)
	im, err := cat.Import(img, ImportOptions{
		Difficulty: Hard, Persona: "linux/web", Source: "custom", Checksum: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if im.Format != FormatQCOW2 {
		t.Fatalf("format = %q, want qcow2", im.Format)
	}
	if im.Difficulty != Hard {
		t.Fatalf("difficulty = %q, want hard", im.Difficulty)
	}
	if im.SHA256 == "" {
		t.Fatal("expected a checksum")
	}
	if im.SizeBytes != 4096 {
		t.Fatalf("size = %d, want 4096", im.SizeBytes)
	}
}

func TestImportRejectsUnknownDifficulty(t *testing.T) {
	cat, _ := Open(filepath.Join(t.TempDir(), "c.json"))
	img := tempImage(t, "x.iso", 10)
	if _, err := cat.Import(img, ImportOptions{Difficulty: "trivial"}); err == nil {
		t.Fatal("expected rejection of an unknown difficulty tier")
	}
}

func TestCatalogPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	cat, _ := Open(path)
	img := tempImage(t, "dc01.vmdk", 2048)
	im, err := cat.Import(img, ImportOptions{Difficulty: Insane, Persona: "windows/dc"})
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get(im.ID)
	if !ok {
		t.Fatal("image did not survive a reopen")
	}
	if got.Format != FormatVMDK || got.Difficulty != Insane {
		t.Fatalf("reopened image lost metadata: %+v", got)
	}
}

func TestListFiltersByDifficultyAndSanitised(t *testing.T) {
	cat, _ := Open(filepath.Join(t.TempDir(), "c.json"))
	e, _ := cat.Import(tempImage(t, "easy.raw", 1), ImportOptions{Difficulty: Easy})
	cat.Import(tempImage(t, "hard.raw", 1), ImportOptions{Difficulty: Hard})

	if got := cat.List(Filter{Difficulty: Easy}); len(got) != 1 || got[0].ID != e.ID {
		t.Fatalf("difficulty filter wrong: %+v", got)
	}
	if got := cat.List(Filter{SanitizedOnly: true}); len(got) != 0 {
		t.Fatal("nothing is sanitised yet")
	}
	if err := cat.MarkSanitized(e.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := cat.List(Filter{SanitizedOnly: true}); len(got) != 1 {
		t.Fatal("the sanitised image should now appear")
	}
}

func TestRemoveForgetsEntryButKeepsFile(t *testing.T) {
	cat, _ := Open(filepath.Join(t.TempDir(), "c.json"))
	img := tempImage(t, "gone.qcow2", 1)
	im, _ := cat.Import(img, ImportOptions{Difficulty: Medium})
	if err := cat.Remove(im.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := cat.Get(im.ID); ok {
		t.Fatal("entry should be gone")
	}
	if _, err := os.Stat(img); err != nil {
		t.Fatal("Remove must NOT delete the image file")
	}
}

func TestRetag(t *testing.T) {
	cat, _ := Open(filepath.Join(t.TempDir(), "c.json"))
	im, _ := cat.Import(tempImage(t, "x.raw", 1), ImportOptions{Difficulty: Easy})
	if err := cat.Retag(im.ID, Insane, []string{"apt28", "loud"}); err != nil {
		t.Fatal(err)
	}
	got, _ := cat.Get(im.ID)
	if got.Difficulty != Insane || len(got.Tags) != 2 {
		t.Fatalf("retag failed: %+v", got)
	}
}

func TestSanitizePlanCoversFlagsCredsWatermark(t *testing.T) {
	im := &Image{Name: "htb-box", ID: "htb-box", Difficulty: Hard, Format: FormatQCOW2}
	plan := im.Plan(DefaultCTFRuleset("deploy-42"))

	var haveFlag, haveCred, haveMark bool
	for _, a := range plan {
		switch a.Kind {
		case ActionRemoveFile:
			if strings.Contains(a.Target, "user.txt") || strings.Contains(a.Target, "root.txt") {
				haveFlag = true
			}
		case ActionResetCred:
			haveCred = true
		case ActionEmbedMark:
			haveMark = true
		}
	}
	if !haveFlag {
		t.Error("plan must remove user.txt/root.txt flags")
	}
	if !haveCred {
		t.Error("plan must reset a known credential")
	}
	if !haveMark {
		t.Error("plan must embed a watermark when one is given")
	}

	report := PlanReport(im, plan)
	if !strings.Contains(report, "sanitisation plan") {
		t.Error("report should be human-readable")
	}
}

func TestBuildArgsMapsActionsToVirtCustomize(t *testing.T) {
	im := &Image{Name: "b", ID: "b"}
	plan := im.Plan(Ruleset{
		FlagPaths:     []string{"/root/root.txt"},
		ResetAccounts: []string{"root"},
		Watermark:     "wm",
		ExtraCommands: []string{"rm -f /root/.bash_history"},
	})
	args, passwords := BuildArgs("/img/box.qcow2", plan)
	joined := strings.Join(args, " ")

	for _, want := range []string{"-a /img/box.qcow2", "--delete /root/root.txt",
		"--password root:password:", "--write /etc/.mirage-mark:wm",
		"--run-command rm -f /root/.bash_history"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q; got: %s", want, joined)
		}
	}
	if _, ok := passwords["root"]; !ok {
		t.Error("expected a generated password for root")
	}
}
