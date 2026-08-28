package honeyd

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// ftpClient is a minimal FTP client for driving the decoy in tests.
type ftpClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dialFTP(t *testing.T, addr string) *ftpClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	c := &ftpClient{t: t, conn: conn, r: bufio.NewReader(conn)}
	c.read() // banner
	return c
}

func (c *ftpClient) read() string {
	c.t.Helper()
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("ftp read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *ftpClient) cmd(format string, args ...any) string {
	c.t.Helper()
	fmt.Fprintf(c.conn, format+"\r\n", args...)
	return c.read()
}

func (c *ftpClient) login(user, pass string) {
	c.t.Helper()
	c.cmd("USER %s", user)
	if resp := c.cmd("PASS %s", pass); !strings.HasPrefix(resp, "230") {
		c.t.Fatalf("login failed: %s", resp)
	}
}

// pasv opens the data connection and returns it.
func (c *ftpClient) pasv() net.Conn {
	c.t.Helper()
	resp := c.cmd("PASV")
	open := strings.Index(resp, "(")
	close := strings.Index(resp, ")")
	if open < 0 || close < 0 {
		c.t.Fatalf("bad PASV reply: %s", resp)
	}
	parts := strings.Split(resp[open+1:close], ",")
	if len(parts) != 6 {
		c.t.Fatalf("bad PASV tuple: %s", resp)
	}
	hi, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
	lo, _ := strconv.Atoi(strings.TrimSpace(parts[5]))
	dc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", hi<<8|lo))
	if err != nil {
		c.t.Fatalf("data connection: %v", err)
	}
	return dc
}

func (c *ftpClient) store(path string, content []byte) {
	c.t.Helper()
	dc := c.pasv()
	fmt.Fprintf(c.conn, "STOR %s\r\n", path)
	c.read() // 150
	dc.Write(content)
	dc.Close()
	c.read() // 226
}

// names returns the filenames in a directory, as parsed from LIST output.
func (c *ftpClient) names(path string) []string {
	c.t.Helper()
	var out []string
	for _, line := range strings.Split(c.list(path), "\r\n") {
		fields := strings.Fields(line)
		if len(fields) >= 8 && !strings.HasPrefix(line, "d") {
			out = append(out, fields[len(fields)-1])
		}
	}
	return out
}

func (c *ftpClient) list(path string) string {
	c.t.Helper()
	dc := c.pasv()
	fmt.Fprintf(c.conn, "LIST %s\r\n", path)
	c.read()
	buf := make([]byte, 65536)
	n, _ := dc.Read(buf)
	dc.Close()
	c.read()
	return string(buf[:n])
}

func TestFTPServesTheGeneratedShare(t *testing.T) {
	_, _, addrs := startFarm(t, ListenerConfig{Service: "ftp", Persona: "linux/fileserver"})
	c := dialFTP(t, addrs["ftp"])
	c.login("backup", "backup")

	listing := c.list("/srv/shares/finance")
	// The canaries sort first, which is the whole point: a sweep hits them
	// before it reaches anything else.
	if !strings.Contains(listing, "!!!_DO_NOT_DELETE_asset_register.xlsx") {
		t.Fatalf("canary missing from the share listing:\n%s", listing)
	}
	if !strings.Contains(listing, "2024") {
		t.Fatalf("the share has no year directories:\n%s", listing)
	}
	years := c.list("/srv/shares/finance/2024/Q1")
	if strings.Count(years, "\n") < 5 {
		t.Fatalf("a quarter directory should hold several documents:\n%s", years)
	}
}

func TestFTPEncryptorRunIsDetectedAndSlowed(t *testing.T) {
	// A short tarpit keeps the test quick; the real default is seconds per
	// operation, which is the point (see TestFTPTarpitSlowsAConfirmedEncryptor).
	_, col, addrs := startFarm(t, ListenerConfig{
		Service: "ftp", Persona: "linux/fileserver",
		Options: map[string]any{"tarpit_max_ms": 20},
	})
	c := dialFTP(t, addrs["ftp"])
	c.login("backup", "backup")

	random := make([]byte, 4096)
	rand.Read(random)

	// Walk the share the way an encryptor does: read, overwrite with random
	// data, rename with a new suffix.
	base := "/srv/shares/finance/2024/Q1"
	names := c.names(base)
	if len(names) < 5 {
		t.Fatalf("not enough files to sweep: %v", names)
	}

	for _, n := range names {
		p := base + "/" + n
		c.store(p, random)
		c.cmd("RNFR %s", p)
		c.cmd("RNTO %s.locked", p)
	}
	// The ransom note, dropped where the sweep finished.
	c.store(base+"/HOW_TO_DECRYPT.txt",
		[]byte("Your files are encrypted.\nContact recovery@protonmail.example\n"+
			"Payment: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"))

	confirmed := col.waitFor(t, "ransomware confirmation", func(e *event.Event) bool {
		return e.GetString("ransomware_signal") == "ransomware-confirmed"
	})
	if confirmed.SeverityID != event.SeverityCritical {
		t.Fatalf("confirmation severity = %s, want critical", confirmed.SeverityID)
	}
	if !hasTechnique(confirmed, "T1486") {
		t.Fatalf("ransomware not mapped to T1486: %+v", confirmed.Mirage.Attack)
	}

	for _, want := range []string{"high-entropy-write", "file-type-destroyed",
		"mass-extension-change", "canary-touched", "ransom-note"} {
		col.waitFor(t, "signal "+want, func(e *event.Event) bool {
			return e.GetString("ransomware_signal") == want
		})
	}

	// The note's contact details are what an incident responder needs first.
	note := col.waitFor(t, "ransom note capture", func(e *event.Event) bool {
		return e.GetString("ransomware_signal") == "ransom-note"
	})
	contacts, _ := note.Get("contacts")
	m, _ := contacts.(map[string][]string)
	if len(m["bitcoin"]) == 0 || len(m["email"]) == 0 {
		t.Fatalf("contacts not extracted from the note: %+v", contacts)
	}
}

func TestFTPTarpitSlowsAConfirmedEncryptor(t *testing.T) {
	// The tarpit is the only defensive action a decoy can safely take: the
	// files are worthless, so every second it costs the encryptor is free.
	_, _, addrs := startFarm(t, ListenerConfig{
		Service: "ftp", Persona: "linux/fileserver",
		Options: map[string]any{"tarpit_max_ms": 400},
	})
	c := dialFTP(t, addrs["ftp"])
	c.login("backup", "backup")

	random := make([]byte, 4096)
	rand.Read(random)
	base := "/srv/shares/hr/2025/Q2"
	names := c.names(base)
	if len(names) < 6 {
		t.Fatalf("not enough files to sweep: %v", names)
	}

	var first, later time.Duration
	for i, name := range names {
		p := base + "/" + name
		start := time.Now()
		c.store(p, random)
		c.cmd("RNFR %s", p)
		c.cmd("RNTO %s.crypt", p)
		elapsed := time.Since(start)
		if i == 0 {
			first = elapsed
		}
		later = elapsed
	}
	if later <= first {
		t.Fatalf("the sweep did not slow down: first %s, last %s", first, later)
	}
	if later < 100*time.Millisecond {
		t.Fatalf("a confirmed encryptor is only delayed by %s per file", later)
	}
}

func TestFTPBrowsingIsNotSlowedDown(t *testing.T) {
	// The tarpit must not touch ordinary use, or the decoy feels wrong to
	// anyone who merely looks around.
	_, _, addrs := startFarm(t, ListenerConfig{Service: "ftp", Persona: "linux/fileserver"})
	c := dialFTP(t, addrs["ftp"])
	c.login("backup", "backup")

	start := time.Now()
	for i := 0; i < 5; i++ {
		c.list("/srv/shares/hr")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("browsing five directories took %s; the tarpit is biting normal use", elapsed)
	}
}
