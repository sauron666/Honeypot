package observer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/event"
)

// These lines are shaped like real DRAKVUF JSON output (procmon, filedelete,
// regmon, injection plugins), so the parser is tested against what the tool
// actually emits rather than against an idealised format.

func TestParsesProcmonExec(t *testing.T) {
	line := `{"Plugin":"procmon","TimeStamp":"1710000000.123000","ProcessName":"cmd.exe",` +
		`"UserId":500,"PID":4321,"PPID":1000,` +
		`"CommandLine":"powershell -enc SQBFAFgA"}`
	s, ok := ParseDrakvufLine("vm-dc01", []byte(line))
	if !ok {
		t.Fatal("a procmon line did not parse")
	}
	if s.Kind != "process" || s.Action != "exec" {
		t.Fatalf("wrong classification: %+v", s)
	}
	if s.PID != 4321 || s.PPID != 1000 {
		t.Fatalf("pids lost: %+v", s)
	}
	if !strings.Contains(s.CommandLine, "powershell -enc") {
		t.Fatalf("command line lost: %q", s.CommandLine)
	}
	if s.DecoyID != "vm-dc01" {
		t.Fatalf("decoy id not stamped: %q", s.DecoyID)
	}
	if s.Time.Year() != 2024 {
		t.Fatalf("timestamp not parsed: %v", s.Time)
	}
}

func TestParsesFileDeleteWithDevicePath(t *testing.T) {
	line := `{"Plugin":"filedelete2","TimeStamp":"1710000001.000000","ProcessName":"vssadmin.exe",` +
		`"PID":5000,"FileName":"\\Device\\HarddiskVolume2\\Users\\bob\\report.docx"}`
	s, ok := ParseDrakvufLine("vm-fs01", []byte(line))
	if !ok {
		t.Fatal("a filedelete line did not parse")
	}
	if s.Kind != "file" || s.Action != "delete" {
		t.Fatalf("wrong classification: %+v", s)
	}
	// The NT device path must be normalised to something readable.
	if !strings.HasPrefix(s.Target, `C:\`) || strings.Contains(s.Target, "HarddiskVolume") {
		t.Fatalf("device path not normalised: %q", s.Target)
	}
}

func TestParsesRegistryPersistence(t *testing.T) {
	line := `{"Plugin":"regmon","TimeStamp":"1710000002.000000","ProcessName":"reg.exe","PID":6000,` +
		`"Operation":"RegSetValue","Key":"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",` +
		`"ValueName":"Updater"}`
	s, ok := ParseDrakvufLine("vm-dc01", []byte(line))
	if !ok {
		t.Fatal("a regmon line did not parse")
	}
	if s.Kind != "registry" || s.Action != "write" {
		t.Fatalf("wrong classification: %+v", s)
	}
	e := SightingToEvent(s, "t", "s", "windows/dc")
	if e.SeverityID != event.SeverityHigh {
		t.Fatalf("a Run-key write should be high severity, got %d", e.SeverityID)
	}
	if !hasTech(e, "T1547.001") {
		t.Fatal("a Run-key write was not mapped to registry persistence")
	}
}

func TestUnmappedPluginIsSkippedNotFatal(t *testing.T) {
	// A DRAKVUF upgrade adds plugins constantly. An unknown one must be skipped,
	// not abort the stream.
	if _, ok := ParseDrakvufLine("vm", []byte(`{"Plugin":"socketmon","TimeStamp":1}`)); ok {
		t.Fatal("an unmapped plugin produced a sighting")
	}
	if _, ok := ParseDrakvufLine("vm", []byte("not json")); ok {
		t.Fatal("a non-JSON line produced a sighting")
	}
	if _, ok := ParseDrakvufLine("vm", []byte("")); ok {
		t.Fatal("an empty line produced a sighting")
	}
}

func TestProcessExecIsHighSignalWithIntent(t *testing.T) {
	// An interactive command inside a decoy is the attacker's hands on a real
	// machine -- not a routine probe.
	s, _ := ParseDrakvufLine("vm-dc01", []byte(
		`{"Plugin":"procmon","TimeStamp":"1710000003.000000","ProcessName":"cmd.exe","PID":1,`+
			`"CommandLine":"whoami /all"}`))
	e := SightingToEvent(s, "t", "s", "windows/dc")
	if e.SeverityID != event.SeverityHigh {
		t.Fatalf("a process exec in a decoy should be high, got %d", e.SeverityID)
	}
	if !hasTech(e, "T1059") || !hasTech(e, "T1057") {
		t.Fatalf("exec of a discovery command was not mapped: %+v", e.Mirage.Attack)
	}
	if e.Mirage.Plane != event.PlaneObserver {
		t.Fatalf("an observer event carries the wrong plane: %q", e.Mirage.Plane)
	}
}

func TestInjectionIsCritical(t *testing.T) {
	s, _ := ParseDrakvufLine("vm-dc01", []byte(
		`{"Plugin":"injection","TimeStamp":"1710000004.000000","ProcessName":"rundll32.exe","PID":7,`+
			`"TargetPID":800,"TargetName":"lsass.exe","Method":"CreateRemoteThread"}`))
	e := SightingToEvent(s, "t", "s", "windows/dc")
	if e.SeverityID != event.SeverityCritical {
		t.Fatalf("process injection should be critical, got %d", e.SeverityID)
	}
	if !hasTech(e, "T1055") {
		t.Fatal("injection was not mapped to T1055")
	}
	if e.GetString("target_pid") != "800" {
		t.Fatalf("injection target pid lost: %q", e.GetString("target_pid"))
	}
}

// fakeRunner replays canned lines as a drakvuf stream, so the Observe loop is
// tested without a hypervisor.
type fakeRunner struct{ lines []string }

func (f fakeRunner) stream(ctx context.Context, bin string, args ...string) (<-chan []byte, error) {
	ch := make(chan []byte)
	go func() {
		defer close(ch)
		for _, l := range f.lines {
			select {
			case ch <- []byte(l):
			case <-ctx.Done():
				return
			}
		}
		<-ctx.Done()
	}()
	return ch, nil
}

func TestObserveStreamsParsedSightings(t *testing.T) {
	d := &Drakvuf{
		bin: "drakvuf",
		run: fakeRunner{lines: []string{
			`{"Plugin":"procmon","TimeStamp":"1710000000.000000","ProcessName":"cmd.exe","PID":1,"CommandLine":"net user"}`,
			`{"Plugin":"heartbeat"}`,
			`{"Plugin":"filedelete2","TimeStamp":"1710000001.000000","ProcessName":"x","PID":2,"FileName":"C:\\a.txt"}`,
		}},
		domainOf: func(id string) (string, string, error) { return "domain-" + id, "profile", nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := d.Observe(ctx, "vm-dc01")
	if err != nil {
		t.Fatal(err)
	}
	var got []drivers.Sighting
	timeout := time.After(3 * time.Second)
	for len(got) < 2 {
		select {
		case s := <-ch:
			got = append(got, s)
		case <-timeout:
			t.Fatalf("only %d sightings streamed", len(got))
		}
	}
	if got[0].Kind != "process" || got[1].Kind != "file" {
		t.Fatalf("stream mis-ordered or mis-parsed: %+v", got)
	}
}

func TestObserveFailsClosedWithoutAResolver(t *testing.T) {
	// The default driver refuses to guess a Xen domain; without the resolver
	// wired, Observe must fail rather than launch against nothing.
	d, err := NewDrakvuf(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.(*Drakvuf).Observe(context.Background(), "vm-x"); err == nil {
		t.Fatal("Observe launched with no domain resolver configured")
	}
}

func TestNoneObserverIsHonest(t *testing.T) {
	n, _ := NewNone(nil)
	if _, err := n.(*None).Observe(context.Background(), "vm"); err != drivers.ErrObserveUnsupported {
		t.Fatalf("the null observer should say it observes nothing, got %v", err)
	}
	if len(NoneInfo().Capabilities) != 0 {
		t.Fatal("the null observer must claim no capabilities")
	}
}

func TestDrakvufDeclaresAgentless(t *testing.T) {
	if !DrakvufInfo().Has(drivers.CapAgentless) {
		t.Fatal("drakvuf must declare it is agentless; that is its whole value")
	}
	if !DrakvufInfo().Experimental {
		t.Fatal("drakvuf must stay experimental until validated on hardware")
	}
}

func TestParsesCryptoAPIHook(t *testing.T) {
	line := `{"Plugin":"apimon","TimeStamp":"1710000005.000000","ProcessName":"ransomware.exe",` +
		`"PID":9000,"API":"BCryptEncrypt","KeyHex":"aabbccdd","Alg":"AES-256"}`
	s, ok := ParseDrakvufLine("vm-dc01", []byte(line))
	if !ok {
		t.Fatal("an apimon/crypto line did not parse")
	}
	if s.Kind != "crypto" || s.Action != "encrypt" {
		t.Fatalf("wrong classification: %+v", s)
	}
	if s.Target != "BCryptEncrypt" {
		t.Fatalf("target should be the API name: %q", s.Target)
	}
	if s.Detail["key_hex"] != "aabbccdd" {
		t.Fatalf("key not captured: %+v", s.Detail)
	}
	e := SightingToEvent(s, "t", "s", "windows/dc")
	if e.SeverityID != event.SeverityCritical {
		t.Fatalf("crypto interception should be critical, got %d", e.SeverityID)
	}
	if !hasTech(e, "T1486") {
		t.Fatal("crypto hook was not mapped to T1486 (Data Encrypted for Impact)")
	}
}

func TestUnmappedApimonIsSkipped(t *testing.T) {
	line := `{"Plugin":"apimon","TimeStamp":"1710000006.000000","ProcessName":"svchost.exe",` +
		`"PID":700,"API":"NtCreateFile"}`
	if _, ok := ParseDrakvufLine("vm", []byte(line)); ok {
		t.Fatal("a non-crypto apimon event should be skipped")
	}
}

func TestBareNumericTimestampStillWorks(t *testing.T) {
	line := `{"Plugin":"procmon","TimeStamp":1710000000.5,"ProcessName":"ls","PID":1,"CommandLine":"ls -la"}`
	s, ok := ParseDrakvufLine("vm", []byte(line))
	if !ok {
		t.Fatal("bare numeric timestamp should still parse")
	}
	if s.Time.Year() != 2024 {
		t.Fatalf("timestamp wrong: %v", s.Time)
	}
}

func TestRunningProcessFallback(t *testing.T) {
	// Real DRAKVUF on Linux emits RunningProcess (initial listing) instead of
	// ProcessName (triggered events). The parser must accept both.
	line := `{"Plugin":"procmon","TimeStamp":"1788109078.076494","PID":1,"PPID":0,"RunningProcess":"swapper/0","Bitness":0}`
	s, ok := ParseDrakvufLine("vm-linux", []byte(line))
	if !ok {
		t.Fatal("RunningProcess line did not parse")
	}
	if s.Process != "swapper/0" {
		t.Fatalf("process name not extracted from RunningProcess: %q", s.Process)
	}
	if s.Kind != "process" {
		t.Fatalf("wrong kind: %q", s.Kind)
	}
}

func TestProcessNameTakesPrecedenceOverRunningProcess(t *testing.T) {
	line := `{"Plugin":"procmon","TimeStamp":"1710000000.000000","ProcessName":"bash","RunningProcess":"old","PID":1,"CommandLine":"bash"}`
	s, ok := ParseDrakvufLine("vm", []byte(line))
	if !ok {
		t.Fatal("line with both fields did not parse")
	}
	if s.Process != "bash" {
		t.Fatalf("ProcessName should take precedence, got %q", s.Process)
	}
}

func TestProbeFailsOnNonXenHost(t *testing.T) {
	d, _ := NewDrakvuf(nil)
	err := d.(*Drakvuf).Probe(context.Background())
	if err == nil {
		t.Skip("this host has drakvuf on PATH, or /proc/xen — skipping")
	}
}

func hasTech(e *event.Event, id string) bool {
	for _, t := range e.Mirage.Attack {
		if t.Technique == id {
			return true
		}
	}
	return false
}
