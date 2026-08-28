package honeyd

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/md4"

	"github.com/sauron666/Honeypot/internal/event"
)

// smbClient is a minimal SMB2 client that performs a real NTLMv2 exchange, so
// the decoy is exercised against a genuine handshake rather than a replayed
// capture.
type smbClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	msg  uint64
	sid  uint64
}

func dialSMB(t *testing.T, addr string) *smbClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	return &smbClient{t: t, conn: conn, r: bufio.NewReader(conn)}
}

func (c *smbClient) header(command uint16) []byte {
	b := make([]byte, 64)
	copy(b[0:4], "\xfeSMB")
	binary.LittleEndian.PutUint16(b[4:6], 64)
	binary.LittleEndian.PutUint16(b[6:8], 1)
	binary.LittleEndian.PutUint16(b[12:14], command)
	binary.LittleEndian.PutUint16(b[14:16], 1)
	binary.LittleEndian.PutUint64(b[24:32], c.msg)
	binary.LittleEndian.PutUint64(b[40:48], c.sid)
	c.msg++
	return b
}

func (c *smbClient) send(msg []byte) []byte {
	c.t.Helper()
	hdr := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	if _, err := c.conn.Write(append(hdr, msg...)); err != nil {
		c.t.Fatalf("smb write: %v", err)
	}
	resp, err := readNetBIOS(c.r)
	if err != nil {
		c.t.Fatalf("smb read: %v", err)
	}
	if len(resp) < 64 {
		c.t.Fatalf("short SMB response: %d bytes", len(resp))
	}
	if sid := binary.LittleEndian.Uint64(resp[40:48]); sid != 0 {
		c.sid = sid
	}
	return resp
}

func (c *smbClient) negotiate() []byte {
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], 2) // dialect count
	binary.LittleEndian.PutUint16(body[4:6], 1) // signing enabled
	body = append(body, 0x02, 0x02, 0x10, 0x02) // dialects 2.0.2 and 2.1
	return c.send(append(c.header(smb2Negotiate), body...))
}

func (c *smbClient) sessionSetup(blob []byte) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)
	body[3] = 1 // signing enabled
	binary.LittleEndian.PutUint16(body[12:14], 64+24)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(blob)))
	return c.send(append(c.header(smb2SessionSetup), append(body, blob...)...))
}

func (c *smbClient) treeConnect(share string) []byte {
	path := utf16le(`\\FS01\` + share)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[4:6], 64+8)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(path)))
	return c.send(append(c.header(smb2TreeConnect), append(body, path...)...))
}

// ntlmNegotiate builds a type 1 message.
func ntlmNegotiate() []byte {
	b := make([]byte, 32)
	copy(b[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:12], 1)
	binary.LittleEndian.PutUint32(b[12:16], 0xE2088297)
	return b
}

// ntlmAuthenticate builds a type 3 message with a real NTLMv2 response.
func ntlmAuthenticate(t *testing.T, domain, user, workstation, password string,
	challenge []byte, targetInfo []byte) []byte {
	t.Helper()

	ntlmHash := ntowfv1(password)
	h := hmac.New(md5.New, ntlmHash)
	h.Write(utf16le(strings.ToUpper(user)))
	h.Write(utf16le(domain))
	ntlmv2Hash := h.Sum(nil)

	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge)

	blob := []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, windowsTime(time.Now()))
	blob = append(blob, ts...)
	blob = append(blob, clientChallenge...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, targetInfo...)
	blob = append(blob, 0, 0, 0, 0)

	proofMac := hmac.New(md5.New, ntlmv2Hash)
	proofMac.Write(challenge)
	proofMac.Write(blob)
	ntResponse := append(proofMac.Sum(nil), blob...)

	d, u, w := utf16le(domain), utf16le(user), utf16le(workstation)
	const headerLen = 64
	payload := []byte{}
	put := func(b []byte, off int, data []byte) {
		binary.LittleEndian.PutUint16(b[off:off+2], uint16(len(data)))
		binary.LittleEndian.PutUint16(b[off+2:off+4], uint16(len(data)))
		binary.LittleEndian.PutUint32(b[off+4:off+8], uint32(headerLen+len(payload)))
		payload = append(payload, data...)
	}
	msg := make([]byte, headerLen)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3)
	put(msg, 12, nil)        // LM response
	put(msg, 20, ntResponse) // NT response
	put(msg, 28, d)
	put(msg, 36, u)
	put(msg, 44, w)
	put(msg, 52, nil) // session key
	binary.LittleEndian.PutUint32(msg[60:64], 0xE2088235)
	return append(msg, payload...)
}

func ntowfv1(password string) []byte {
	h := md4.New()
	h.Write(utf16le(password))
	return h.Sum(nil)
}

// extractChallengeAndInfo pulls the server challenge and target info out of the
// decoy's NTLMSSP_CHALLENGE.
func extractChallengeAndInfo(t *testing.T, resp []byte) ([]byte, []byte) {
	t.Helper()
	ntlm := findNTLMSSP(resp)
	if ntlm == nil {
		t.Fatal("the decoy did not send an NTLMSSP challenge")
	}
	if messageType(ntlm) != 2 {
		t.Fatalf("expected a CHALLENGE message, got type %d", messageType(ntlm))
	}
	if len(ntlm) < 48 {
		t.Fatal("challenge message is truncated")
	}
	challenge := append([]byte(nil), ntlm[24:32]...)

	infoLen := int(binary.LittleEndian.Uint16(ntlm[40:42]))
	infoOff := int(binary.LittleEndian.Uint32(ntlm[44:48]))
	if infoOff+infoLen > len(ntlm) {
		t.Fatalf("target info points outside the message (off=%d len=%d, have %d)",
			infoOff, infoLen, len(ntlm))
	}
	return challenge, append([]byte(nil), ntlm[infoOff:infoOff+infoLen]...)
}

func TestSMBCapturesNetNTLMv2(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "smb", Persona: "linux/fileserver"})
	c := dialSMB(t, addrs["smb"])

	neg := c.negotiate()
	if binary.LittleEndian.Uint32(neg[8:12]) != statusSuccess {
		t.Fatalf("negotiate failed with status 0x%08x", binary.LittleEndian.Uint32(neg[8:12]))
	}
	if dialect := binary.LittleEndian.Uint16(neg[64+4 : 64+6]); dialect != 0x0210 {
		t.Fatalf("dialect = 0x%04x, want 0x0210", dialect)
	}

	// Step one: the client offers NTLM, the decoy answers with its challenge.
	resp := c.sessionSetup(ntlmNegotiate())
	if status := binary.LittleEndian.Uint32(resp[8:12]); status != statusMoreProcessingRequired {
		t.Fatalf("session setup status = 0x%08x, want MORE_PROCESSING_REQUIRED", status)
	}
	challenge, targetInfo := extractChallengeAndInfo(t, resp)
	if len(targetInfo) == 0 {
		t.Fatal("no target info: a real client cannot compute NTLMv2 without it")
	}

	// Step two: the client authenticates. This is the capture.
	auth := ntlmAuthenticate(t, "CORP", "svc_backup", "ATTACKER-PC", "Autumn2025!",
		challenge, targetInfo)
	c.sessionSetup(auth)

	e := col.waitFor(t, "smb authentication", func(e *event.Event) bool {
		return e.ClassUID == event.ClassAuthentication && e.Mirage.Service == "smb"
	})
	if e.GetString("username") != "svc_backup" {
		t.Fatalf("username = %q", e.GetString("username"))
	}
	if e.GetString("domain") != "CORP" {
		t.Fatalf("domain = %q", e.GetString("domain"))
	}
	// The workstation name survives IP rotation, which makes it one of the
	// most durable identifiers an attacker leaves behind.
	if e.GetString("workstation") != "ATTACKER-PC" {
		t.Fatalf("workstation = %q", e.GetString("workstation"))
	}
	if e.GetString("hash_format") != "NetNTLMv2" {
		t.Fatalf("hash format = %q", e.GetString("hash_format"))
	}

	// The hash must be in the exact shape hashcat -m 5600 expects:
	// user::domain:challenge:proof:blob
	hash := e.GetString("hash")
	parts := strings.Split(hash, ":")
	if len(parts) != 6 || parts[1] != "" {
		t.Fatalf("hash is not in NetNTLMv2 format: %q", hash)
	}
	if parts[0] != "svc_backup" || parts[2] != "CORP" {
		t.Fatalf("hash names the wrong principal: %q", hash)
	}
	if parts[3] != hex.EncodeToString(challenge) {
		t.Fatalf("hash carries the wrong server challenge: %q vs %q",
			parts[3], hex.EncodeToString(challenge))
	}
	if len(parts[4]) != 32 {
		t.Fatalf("NT proof string should be 16 bytes, got %d hex chars", len(parts[4]))
	}
	if _, err := hex.DecodeString(parts[5]); err != nil || len(parts[5]) < 64 {
		t.Fatalf("the NTLMv2 blob is malformed: %v", err)
	}

	col.waitFor(t, "credential record", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCredentialOffer && e.GetString("auth_method") == "ntlmssp"
	})
}

func TestSMBTreeConnectRevealsWhatTheyWant(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "smb", Persona: "linux/fileserver"})
	c := dialSMB(t, addrs["smb"])
	c.negotiate()
	resp := c.sessionSetup(ntlmNegotiate())
	challenge, info := extractChallengeAndInfo(t, resp)
	c.sessionSetup(ntlmAuthenticate(t, "CORP", "admin", "PC1", "pw", challenge, info))

	tc := c.treeConnect("Backups")
	if status := binary.LittleEndian.Uint32(tc[8:12]); status != statusSuccess {
		t.Fatalf("tree connect status = 0x%08x", status)
	}

	e := col.waitFor(t, "tree connect", func(e *event.Event) bool {
		return e.GetString("share") == "Backups"
	})
	// Which share they reach for says what they came for.
	if e.SeverityID < event.SeverityHigh {
		t.Fatalf("a connect to Backups scored %s; that is what ransomware looks for first",
			e.SeverityID)
	}
}

func TestSMBHandlesGarbageWithoutPanicking(t *testing.T) {
	// Port 445 attracts every scanner and every broken exploit on the internet.
	_, col, addrs := startFarm(t, ListenerConfig{Service: "smb", Persona: "linux/fileserver"})

	for _, payload := range [][]byte{
		{0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef},
		append([]byte{0x00, 0x00, 0x00, 0x40}, make([]byte, 64)...),
		{0x00, 0x00, 0x00, 0x10, 0xfe, 'S', 'M', 'B'},
	} {
		conn, err := net.Dial("tcp", addrs["smb"])
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write(payload)
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Close()
	}

	// The decoy must survive and keep serving.
	c := dialSMB(t, addrs["smb"])
	if neg := c.negotiate(); binary.LittleEndian.Uint32(neg[8:12]) != statusSuccess {
		t.Fatal("the service stopped working after malformed input")
	}
	// Malformed input must still be recorded: garbage on 445 is evidence too.
	col.waitFor(t, "a record of the malformed traffic", func(e *event.Event) bool {
		return e.Mirage.Service == "smb"
	})
}

func TestSMB1NegotiateGetsAnSMB2Answer(t *testing.T) {
	// Old clients and many scanners still open with SMB1. Answering in SMB2 is
	// what every current server does.
	_, _, addrs := startFarm(t, ListenerConfig{Service: "smb", Persona: "linux/fileserver"})
	conn, err := net.Dial("tcp", addrs["smb"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	smb1 := append([]byte{0xff, 'S', 'M', 'B', 0x72}, make([]byte, 60)...)
	hdr := []byte{0, 0, 0, byte(len(smb1))}
	conn.Write(append(hdr, smb1...))

	r := bufio.NewReader(conn)
	resp, err := readNetBIOS(r)
	if err != nil {
		t.Fatalf("no answer to SMB1 negotiate: %v", err)
	}
	if len(resp) < 4 || string(resp[:4]) != "\xfeSMB" {
		t.Fatalf("expected an SMB2 answer, got % x", resp[:min(len(resp), 8)])
	}
}
