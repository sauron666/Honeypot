package compute

import (
	"context"
	"strings"
	"testing"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// fakeRunner records the commands it is asked to run and returns canned output,
// so the Hyper-V driver's cmdlet construction and parsing can be tested without
// a Windows host.
type fakeRunner struct {
	calls []string
	reply func(script string) (string, error)
}

func (f *fakeRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	full := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, full)
	// The script is the last argument (after -Command).
	script := args[len(args)-1]
	if f.reply != nil {
		return f.reply(script)
	}
	return "", nil
}

func newTestHyperV(t *testing.T, fr *fakeRunner, host string) *HyperV {
	t.Helper()
	h := &HyperV{run: fr, ps: "pwsh"}
	if host != "" {
		h.host = host
		h.extra = []string{"ssh", host}
	}
	return h
}

func TestHyperVListParsesJSON(t *testing.T) {
	fr := &fakeRunner{reply: func(script string) (string, error) {
		return `[{"Name":"web01","State":"Running"},{"Name":"db01","State":"Off"}]`, nil
	}}
	h := newTestHyperV(t, fr, "")
	list, err := h.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(list))
	}
	if list[0].State != drivers.StateRunning || list[1].State != drivers.StateStopped {
		t.Fatalf("state mapping wrong: %+v", list)
	}
}

func TestHyperVStatusAbsentWhenEmpty(t *testing.T) {
	fr := &fakeRunner{reply: func(string) (string, error) { return "", nil }}
	h := newTestHyperV(t, fr, "")
	st, _ := h.Status(context.Background(), "ghost")
	if st.State != drivers.StateAbsent {
		t.Fatalf("empty Get-VM should be absent, got %q", st.State)
	}
}

func TestHyperVPowerAndSnapshotCmdlets(t *testing.T) {
	fr := &fakeRunner{}
	h := newTestHyperV(t, fr, "")
	h.Start(context.Background(), "web01")
	h.Stop(context.Background(), "web01")
	h.Snapshot(context.Background(), "web01", "clean")
	h.Revert(context.Background(), "web01", "clean")

	joined := strings.Join(fr.calls, "\n")
	for _, want := range []string{"Start-VM -Name 'web01'", "Stop-VM -Name 'web01' -Force",
		"Checkpoint-VM -Name 'web01' -SnapshotName 'clean'",
		"Restore-VMCheckpoint -VMName 'web01' -Name 'clean'"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing cmdlet %q in:\n%s", want, joined)
		}
	}
}

func TestHyperVRunsOverSSHWhenHostSet(t *testing.T) {
	fr := &fakeRunner{}
	h := newTestHyperV(t, fr, "admin@hv01")
	h.Start(context.Background(), "web01")
	if len(fr.calls) == 0 || !strings.HasPrefix(fr.calls[0], "ssh admin@hv01 pwsh") {
		t.Fatalf("expected an ssh-wrapped pwsh call, got: %v", fr.calls)
	}
}

func TestHyperVQuotesNames(t *testing.T) {
	fr := &fakeRunner{}
	h := newTestHyperV(t, fr, "")
	// A name with a quote must not break the cmdlet.
	h.Start(context.Background(), "we'b")
	if !strings.Contains(fr.calls[0], "'we''b'") {
		t.Fatalf("single quote not escaped: %v", fr.calls)
	}
}

func TestHyperVCreateAdoptsExisting(t *testing.T) {
	fr := &fakeRunner{reply: func(script string) (string, error) {
		if strings.Contains(script, "Get-VM") {
			return `[{"Name":"web01","State":"Off"}]`, nil
		}
		return "", nil
	}}
	h := newTestHyperV(t, fr, "")
	st, err := h.Create(context.Background(), drivers.DecoySpec{ID: "d", Name: "web01"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Handle != "hyperv/web01" {
		t.Fatalf("expected to adopt web01, got %q", st.Handle)
	}
}

func TestHyperVIsExperimental(t *testing.T) {
	if !HyperVInfo().Experimental {
		t.Error("Hyper-V driver must be marked experimental until validated on a live host")
	}
}
