package assure

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func score(t *testing.T, p DecoyProfile) Detectability {
	t.Helper()
	f := &Fingerprinter{Timeout: 2 * time.Second}
	rep := f.Run(context.Background(), []DecoyProfile{p})
	if len(rep.Decoys) != 1 {
		t.Fatalf("got %d results", len(rep.Decoys))
	}
	return rep.Decoys[0]
}

func hasCheck(d Detectability, name string) *FPFinding {
	for i := range d.Findings {
		if d.Findings[i].Check == name {
			return &d.Findings[i]
		}
	}
	return nil
}

// livedIn is a profile with nothing wrong with it, used as the baseline.
func livedIn() DecoyProfile {
	return DecoyProfile{
		DecoyID: "dcy-ok", Persona: "linux/web", Hostname: "web01",
		OS: "Debian GNU/Linux 12", UptimeDays: 210, HistoryBytes: 900, LogLines: 4000,
		Endpoints: map[string]string{},
	}
}

func TestAWellBuiltDecoyScoresZero(t *testing.T) {
	d := score(t, livedIn())
	if d.Score != 0 {
		t.Fatalf("a lived-in decoy scored %d: %+v", d.Score, d.Findings)
	}
	if !strings.Contains(d.Verdict, "nothing") {
		t.Errorf("verdict = %q", d.Verdict)
	}
}

func TestFingerprintCatchesAMachineWithNoPast(t *testing.T) {
	// The most reliable honeypot tell there is: a host that has never been
	// used by anyone.
	p := livedIn()
	p.UptimeDays = 3
	p.HistoryBytes = 0
	p.LogLines = 0

	d := score(t, p)
	for _, want := range []string{"uptime-too-short", "no-shell-history", "empty-logs"} {
		f := hasCheck(d, want)
		if f == nil {
			t.Errorf("check %s did not fire", want)
			continue
		}
		if f.Fix == "" {
			t.Errorf("check %s reports a problem with no way to fix it", want)
		}
	}
	if d.Score < 45 {
		t.Fatalf("an empty machine scored only %d", d.Score)
	}
}

func TestFingerprintCatchesAnImplausibleServiceMix(t *testing.T) {
	p := livedIn()
	// A PLC and a mail server on one address is a honeypot advertising itself,
	// visible from a port scan before anyone connects.
	p.Endpoints = map[string]string{"modbus": "127.0.0.1:1", "smtp": "127.0.0.1:2"}

	d := score(t, p)
	f := hasCheck(d, "implausible-service-mix")
	if f == nil {
		t.Fatalf("the service mix was not flagged: %+v", d.Findings)
	}
	if !strings.Contains(f.Detail, "modbus") || !strings.Contains(f.Detail, "smtp") {
		t.Errorf("the finding should name both services: %q", f.Detail)
	}
}

func TestFingerprintCatchesAKnownHoneypotBanner(t *testing.T) {
	addr := listenerSaying(t, "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n")
	p := livedIn()
	p.Endpoints = map[string]string{"ssh": addr}

	d := score(t, p)
	f := hasCheck(d, "known-honeypot-banner")
	if f == nil {
		t.Fatalf("Cowrie's default banner was not recognised: %+v", d.Findings)
	}
	if !strings.Contains(f.Detail, "Cowrie") {
		t.Errorf("the finding should name what it matched: %q", f.Detail)
	}
	if f.Weight < 30 {
		t.Errorf("a published honeypot signature should weigh heavily, got %d", f.Weight)
	}
}

func TestFingerprintCatchesAnInstantPasswordRefusal(t *testing.T) {
	// Real services are slow to say no. An instant refusal is one of the
	// cheapest checks an operator can run.
	addr := telnetLike(t, 0)
	p := livedIn()
	p.Endpoints = map[string]string{"telnet": addr}

	d := score(t, p)
	if hasCheck(d, "instant-auth-failure") == nil {
		t.Fatalf("an instant refusal was not flagged: %+v", d.Findings)
	}

	// A service that delays must not be flagged.
	slow := telnetLike(t, 700*time.Millisecond)
	p.Endpoints = map[string]string{"telnet": slow}
	if f := hasCheck(score(t, p), "instant-auth-failure"); f != nil {
		t.Fatalf("a service that delays was flagged anyway: %q", f.Detail)
	}
}

func TestFingerprintCatchesServicesThatDisagreeAboutTheOS(t *testing.T) {
	// A host whose SSH banner says Debian and whose web server says IIS is not
	// a host.
	sshAddr := listenerSaying(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n")
	httpAddr := httpSaying(t, "Microsoft-IIS/10.0")

	p := livedIn()
	p.OS = "Debian GNU/Linux 12"
	p.Endpoints = map[string]string{"ssh": sshAddr, "http": httpAddr}

	d := score(t, p)
	f := hasCheck(d, "os-inconsistency")
	if f == nil {
		t.Fatalf("the disagreement was not flagged: %+v", d.Findings)
	}
	if !strings.Contains(f.Detail, "windows") || !strings.Contains(f.Detail, "linux") {
		t.Errorf("the finding should say who claims what: %q", f.Detail)
	}
}

func TestConsistentServicesAreNotFlagged(t *testing.T) {
	sshAddr := listenerSaying(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n")
	httpAddr := httpSaying(t, "nginx/1.22.1")

	p := livedIn()
	p.Endpoints = map[string]string{"ssh": sshAddr, "http": httpAddr}
	if f := hasCheck(score(t, p), "os-inconsistency"); f != nil {
		t.Fatalf("consistent services were flagged: %q", f.Detail)
	}
}

func TestReportRanksTheWorstDecoyFirst(t *testing.T) {
	good := livedIn()
	good.DecoyID = "dcy-good"
	bad := livedIn()
	bad.DecoyID = "dcy-bad"
	bad.UptimeDays, bad.HistoryBytes, bad.LogLines = 1, 0, 0

	f := &Fingerprinter{Timeout: time.Second}
	rep := f.Run(context.Background(), []DecoyProfile{good, bad})

	if rep.Decoys[0].DecoyID != "dcy-bad" {
		t.Fatalf("the worst decoy is not first: %v", rep.Decoys[0].DecoyID)
	}
	if rep.WorstScore != rep.Decoys[0].Score {
		t.Errorf("worst score = %d, first decoy = %d", rep.WorstScore, rep.Decoys[0].Score)
	}
	if !strings.Contains(rep.Summary, "dcy-bad") {
		t.Errorf("the summary should name the worst decoy: %q", rep.Summary)
	}
}

// --- helpers ----------------------------------------------------------------

func listenerSaying(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write([]byte(banner))
				time.Sleep(50 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().String()
}

func httpSaying(t *testing.T, server string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Length: 0\r\n"+
					"Connection: close\r\n\r\n", server)
			}()
		}
	}()
	return ln.Addr().String()
}

// telnetLike answers a login exchange, refusing after the given delay.
func telnetLike(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				br := bufio.NewReader(c)
				fmt.Fprint(c, "\r\nhost login: ")
				br.ReadString('\n')
				fmt.Fprint(c, "Password: ")
				br.ReadString('\n')
				time.Sleep(delay)
				fmt.Fprint(c, "\r\nLogin incorrect\r\n")
			}()
		}
	}()
	return ln.Addr().String()
}
