package honeyd

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("smb", newSMB) }

// smbSvc answers SMB2 on port 445 -- the most scanned port in any corporate
// network, and the one an attacker reaches for first after landing.
//
// The prize is the NTLM exchange. The decoy chooses the server challenge, so an
// authentication attempt yields a NetNTLMv2 hash in the exact format hashcat
// and john expect. That is real, actionable evidence: it names the account, the
// domain and the workstation the attacker came from, and it is crackable
// offline. Responder built a whole discipline on this; here it is a side effect
// of a decoy answering the door.
//
// Scope note: this implements negotiation, session setup and tree connect.
// File operations return ACCESS_DENIED -- a completely ordinary outcome for an
// account without share permissions. Serving files over SMB2 needs validation
// against real Windows clients before it would be honest to claim it, so the
// ransomware engine currently watches the FTP share instead.
type smbSvc struct {
	p          *Persona
	domain     string
	shares     []string
	acceptAuth bool
}

func newSMB(p *Persona, opts map[string]any) (Service, error) {
	s := &smbSvc{
		p:      p,
		domain: strings.ToUpper(strings.Split(p.Domain, ".")[0]),
		shares: []string{"Finance$", "HR$", "Backups", "IT", "Public"},
		// Accepting the session keeps the attacker moving to tree connect,
		// which tells us which shares they were hunting for.
		acceptAuth: true,
	}
	if v, ok := opts["domain"].(string); ok && v != "" {
		s.domain = strings.ToUpper(v)
	}
	if v, ok := opts["accept_auth"].(bool); ok {
		s.acceptAuth = v
	}
	return s, nil
}

func (s *smbSvc) Type() string { return "smb" }

// SMB2 command codes.
const (
	smb2Negotiate      = 0x0000
	smb2SessionSetup   = 0x0001
	smb2Logoff         = 0x0002
	smb2TreeConnect    = 0x0003
	smb2TreeDisconnect = 0x0004
	smb2Create         = 0x0005
	smb2Close          = 0x0006
	smb2Read           = 0x0008
	smb2Write          = 0x0009
	smb2QueryDirectory = 0x000e
	smb2QueryInfo      = 0x0010
)

// NT status codes.
const (
	statusSuccess                = 0x00000000
	statusMoreProcessingRequired = 0xC0000016
	statusLogonFailure           = 0xC000006D
	statusAccessDenied           = 0xC0000022
	statusNotSupported           = 0xC00000BB
	statusBadNetworkName         = 0xC00000CC
)

type smbHeader struct {
	Command   uint16
	MessageID uint64
	TreeID    uint32
	SessionID uint64
	CreditReq uint16
}

func (s *smbSvc) Serve(ctx context.Context, conn net.Conn, sess *Session) error {
	r := bufio.NewReader(conn)

	var (
		challenge [8]byte
		sessionID uint64
	)
	if _, err := rand.Read(challenge[:]); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))

		msg, err := readNetBIOS(r)
		if err != nil {
			return nil
		}
		sess.Record("in", msg[:min(len(msg), 256)])

		// An SMB1 negotiate arrives from clients that still start there. The
		// modern answer is to reply in SMB2, which every current client accepts.
		if len(msg) >= 4 && msg[0] == 0xff && string(msg[1:4]) == "SMB" {
			sess.Note(event.SeverityLow, "client opened with an SMB1 negotiate")
			if err := writeNetBIOS(conn, s.negotiateResponse(smbHeader{MessageID: 0})); err != nil {
				return err
			}
			continue
		}
		if len(msg) < 64 || string(msg[:4]) != "\xfeSMB" {
			sess.Note(event.SeverityMedium, "non-SMB payload on the SMB port (%d bytes)", len(msg))
			return nil
		}

		hdr := parseSMB2Header(msg)
		body := msg[64:]

		var resp []byte
		switch hdr.Command {
		case smb2Negotiate:
			resp = s.negotiateResponse(hdr)

		case smb2SessionSetup:
			var status uint32
			resp, status, sessionID = s.sessionSetup(hdr, body, challenge, sessionID, sess)
			_ = status

		case smb2TreeConnect:
			resp = s.treeConnect(hdr, body, sess)

		case smb2Create:
			// An authenticated account without share permissions is the most
			// ordinary outcome on any real network.
			name := readCreateName(body)
			sev := event.SeverityMedium
			e := sess.Event(event.ClassSMBActivity, 1, sev).
				WithMessage("SMB open attempt: %s", name).
				WithAttack(event.Technique{Tactic: "TA0007", Technique: "T1135", Name: "Network Share Discovery"})
			e.Set("path", name)
			sess.Emit(e)
			resp = errorResponse(hdr, statusAccessDenied)

		case smb2TreeDisconnect:
			resp = simpleResponse(hdr, statusSuccess, []byte{0x04, 0x00, 0x00, 0x00})

		case smb2Logoff:
			resp = simpleResponse(hdr, statusSuccess, []byte{0x04, 0x00, 0x00, 0x00})

		case smb2Close, smb2Read, smb2Write, smb2QueryDirectory, smb2QueryInfo:
			resp = errorResponse(hdr, statusAccessDenied)

		default:
			resp = errorResponse(hdr, statusNotSupported)
		}

		if err := writeNetBIOS(conn, resp); err != nil {
			return err
		}
	}
}

func parseSMB2Header(b []byte) smbHeader {
	return smbHeader{
		CreditReq: binary.LittleEndian.Uint16(b[14:16]),
		Command:   binary.LittleEndian.Uint16(b[12:14]),
		MessageID: binary.LittleEndian.Uint64(b[24:32]),
		TreeID:    binary.LittleEndian.Uint32(b[36:40]),
		SessionID: binary.LittleEndian.Uint64(b[40:48]),
	}
}

// buildHeader writes a 64-byte SMB2 response header.
func buildHeader(h smbHeader, status uint32, sessionID uint64) []byte {
	b := make([]byte, 64)
	copy(b[0:4], "\xfeSMB")
	binary.LittleEndian.PutUint16(b[4:6], 64) // structure size
	binary.LittleEndian.PutUint16(b[6:8], 1)  // credit charge
	binary.LittleEndian.PutUint32(b[8:12], status)
	binary.LittleEndian.PutUint16(b[12:14], h.Command)
	binary.LittleEndian.PutUint16(b[14:16], 1)          // credits granted
	binary.LittleEndian.PutUint32(b[16:20], 0x00000001) // SMB2_FLAGS_SERVER_TO_REDIR
	binary.LittleEndian.PutUint64(b[24:32], h.MessageID)
	binary.LittleEndian.PutUint32(b[36:40], h.TreeID)
	binary.LittleEndian.PutUint64(b[40:48], sessionID)
	return b
}

func simpleResponse(h smbHeader, status uint32, body []byte) []byte {
	return append(buildHeader(h, status, h.SessionID), body...)
}

func errorResponse(h smbHeader, status uint32) []byte {
	// An SMB2 error response body: StructureSize 9, reserved, byte count 0.
	return simpleResponse(h, status, []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func (s *smbSvc) negotiateResponse(h smbHeader) []byte {
	h.Command = smb2Negotiate
	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65)           // structure size
	binary.LittleEndian.PutUint16(body[2:4], 0x0001)       // signing enabled, not required
	binary.LittleEndian.PutUint16(body[4:6], 0x0210)       // dialect 2.1: widely supported, no encryption to fake
	rand.Read(body[8:24])                                  // server GUID
	binary.LittleEndian.PutUint32(body[24:28], 0x00000001) // DFS capability
	binary.LittleEndian.PutUint32(body[28:32], 0x00800000) // max transact
	binary.LittleEndian.PutUint32(body[32:36], 0x00800000) // max read
	binary.LittleEndian.PutUint32(body[36:40], 0x00800000) // max write
	binary.LittleEndian.PutUint64(body[40:48], windowsTime(time.Now()))
	binary.LittleEndian.PutUint64(body[48:56], windowsTime(s.p.BootTime))
	binary.LittleEndian.PutUint16(body[56:58], 128) // security buffer offset
	binary.LittleEndian.PutUint16(body[58:60], 0)   // no blob: clients fall back to raw NTLMSSP
	return simpleResponse(h, statusSuccess, body)
}

// sessionSetup drives the NTLM exchange and captures the result.
func (s *smbSvc) sessionSetup(h smbHeader, body []byte, challenge [8]byte,
	sessionID uint64, sess *Session) ([]byte, uint32, uint64) {

	h.Command = smb2SessionSetup
	blob := extractSecurityBuffer(body)
	ntlm := findNTLMSSP(blob)

	if ntlm == nil {
		return simpleResponse(h, statusLogonFailure, sessionSetupBody(nil)), statusLogonFailure, sessionID
	}
	switch messageType(ntlm) {
	case 1: // NEGOTIATE: answer with our challenge
		if sessionID == 0 {
			var idBytes [8]byte
			rand.Read(idBytes[:])
			sessionID = binary.LittleEndian.Uint64(idBytes[:]) | 1
		}
		hdr := buildHeader(h, statusMoreProcessingRequired, sessionID)
		return append(hdr, sessionSetupBody(s.ntlmChallenge(challenge))...),
			statusMoreProcessingRequired, sessionID

	case 3: // AUTHENTICATE: the payload we came for
		auth, err := parseNTLMAuth(ntlm)
		if err != nil {
			sess.Note(event.SeverityMedium, "malformed NTLM authenticate message: %v", err)
			return simpleResponse(h, statusLogonFailure, sessionSetupBody(nil)), statusLogonFailure, sessionID
		}
		s.recordNTLM(auth, challenge, sess)

		status := uint32(statusLogonFailure)
		if s.acceptAuth {
			status = statusSuccess
		}
		hdr := buildHeader(h, status, sessionID)
		return append(hdr, sessionSetupBody(nil)...), status, sessionID

	default:
		return simpleResponse(h, statusLogonFailure, sessionSetupBody(nil)), statusLogonFailure, sessionID
	}
}

func sessionSetupBody(blob []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // structure size
	binary.LittleEndian.PutUint16(body[2:4], 0) // session flags
	binary.LittleEndian.PutUint16(body[4:6], 72)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(blob)))
	return append(body, blob...)
}

func (s *smbSvc) treeConnect(h smbHeader, body []byte, sess *Session) []byte {
	h.Command = smb2TreeConnect
	share := readTreeConnectPath(body)

	// Which share an attacker asks for says what they came for: Backups and
	// Finance$ mean something very different from IPC$.
	sev := event.SeverityMedium
	if isInterestingShare(share) {
		sev = event.SeverityHigh
	}
	e := sess.Event(event.ClassSMBActivity, 2, sev).
		WithMessage("SMB tree connect: %s", share).
		WithAttack(event.Technique{Tactic: "TA0007", Technique: "T1135", Name: "Network Share Discovery"})
	e.Set("share", share)
	sess.Emit(e)

	if share == "" {
		return errorResponse(h, statusBadNetworkName)
	}
	body2 := make([]byte, 16)
	binary.LittleEndian.PutUint16(body2[0:2], 16) // structure size
	body2[2] = 0x01                               // share type: disk
	binary.LittleEndian.PutUint32(body2[8:12], 0)
	binary.LittleEndian.PutUint32(body2[12:16], 0x001f01ff) // maximal access
	hdr := buildHeader(h, statusSuccess, h.SessionID)
	binary.LittleEndian.PutUint32(hdr[36:40], 1) // tree id
	return append(hdr, body2...)
}

func isInterestingShare(s string) bool {
	l := strings.ToLower(s)
	for _, n := range []string{"backup", "finance", "hr", "admin$", "c$", "sysvol", "netlogon"} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

// --- NTLM -------------------------------------------------------------------

// NTLMAuth is what an NTLMSSP_AUTHENTICATE message tells us.
type NTLMAuth struct {
	Domain      string
	User        string
	Workstation string
	LMResponse  []byte
	NTResponse  []byte
}

func (s *smbSvc) recordNTLM(a NTLMAuth, challenge [8]byte, sess *Session) {
	hash, format := netNTLMHash(a, challenge)

	sess.AddCredential(Credential{
		Username: a.User, Method: "ntlmssp", Accepted: s.acceptAuth,
		KeyType: format, KeyPrint: hash,
	})

	e := sess.Event(event.ClassAuthentication, 1, event.SeverityHigh).
		WithMessage("SMB authentication from %s\\%s on workstation %s", a.Domain, a.User, a.Workstation).
		WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1110", Name: "Brute Force"})
	e.Actor = &event.Actor{User: a.User, Session: sess.ID}
	e.Set("username", a.User).
		Set("domain", a.Domain).
		// The workstation name identifies the attacking machine, and it does
		// not change when they rotate IP addresses.
		Set("workstation", a.Workstation).
		Set("server_challenge", hex.EncodeToString(challenge[:])).
		Set("hash_format", format).
		Set("hash", hash).
		Set("crackable", "paste into hashcat -m 5600 (NetNTLMv2) or -m 5500 (NetNTLMv1)")
	sess.Emit(e)
}

// netNTLMHash renders the capture in the format cracking tools expect.
func netNTLMHash(a NTLMAuth, challenge [8]byte) (string, string) {
	c := hex.EncodeToString(challenge[:])
	if len(a.NTResponse) > 24 {
		// NTLMv2: user::domain:challenge:NTProofStr:blob
		proof := hex.EncodeToString(a.NTResponse[:16])
		blob := hex.EncodeToString(a.NTResponse[16:])
		return fmt.Sprintf("%s::%s:%s:%s:%s", a.User, a.Domain, c, proof, blob), "NetNTLMv2"
	}
	// NTLMv1: user::domain:LMresponse:NTresponse:challenge
	return fmt.Sprintf("%s::%s:%s:%s:%s", a.User, a.Domain,
		hex.EncodeToString(a.LMResponse), hex.EncodeToString(a.NTResponse), c), "NetNTLMv1"
}

// ntlmChallenge builds an NTLMSSP_CHALLENGE carrying our server challenge.
func (s *smbSvc) ntlmChallenge(challenge [8]byte) []byte {
	target := utf16le(s.domain)
	info := s.targetInfo()

	msg := make([]byte, 56)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2) // CHALLENGE

	targetOffset := uint32(56)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(msg[16:20], targetOffset)

	// Unicode | Request Target | NTLM | Always Sign | Target Type Domain |
	// Extended session security | Target Info | Version | 128-bit | Key exchange
	binary.LittleEndian.PutUint32(msg[20:24], 0xE2898235)
	copy(msg[24:32], challenge[:])

	infoOffset := targetOffset + uint32(len(target))
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(msg[44:48], infoOffset)
	// Version: Windows Server 2019 build 17763, NTLM revision 15.
	copy(msg[48:56], []byte{10, 0, 0x63, 0x45, 0, 0, 0, 15})

	msg = append(msg, target...)
	return append(msg, info...)
}

// targetInfo builds the AV pair list a client needs to compute NTLMv2.
func (s *smbSvc) targetInfo() []byte {
	pair := func(id uint16, value []byte) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint16(b[0:2], id)
		binary.LittleEndian.PutUint16(b[2:4], uint16(len(value)))
		return append(b, value...)
	}
	host := strings.ToUpper(s.p.Hostname)
	var out []byte
	out = append(out, pair(2, utf16le(s.domain))...)                    // NetBIOS domain
	out = append(out, pair(1, utf16le(host))...)                        // NetBIOS computer
	out = append(out, pair(4, utf16le(strings.ToLower(s.p.Domain)))...) // DNS domain
	out = append(out, pair(3, utf16le(strings.ToLower(host+"."+s.p.Domain)))...)
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, windowsTime(time.Now()))
	out = append(out, pair(7, ts)...)  // timestamp
	out = append(out, pair(0, nil)...) // EOL
	return out
}

func parseNTLMAuth(b []byte) (NTLMAuth, error) {
	var a NTLMAuth
	if len(b) < 64 {
		return a, errors.New("authenticate message is too short")
	}
	field := func(off int) ([]byte, error) {
		l := int(binary.LittleEndian.Uint16(b[off : off+2]))
		o := int(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		if l == 0 {
			return nil, nil
		}
		if o < 0 || l < 0 || o+l > len(b) {
			return nil, fmt.Errorf("field at offset %d points outside the message", off)
		}
		return b[o : o+l], nil
	}
	var err error
	if a.LMResponse, err = field(12); err != nil {
		return a, err
	}
	if a.NTResponse, err = field(20); err != nil {
		return a, err
	}
	domain, err := field(28)
	if err != nil {
		return a, err
	}
	user, err := field(36)
	if err != nil {
		return a, err
	}
	ws, err := field(44)
	if err != nil {
		return a, err
	}
	a.Domain, a.User, a.Workstation = fromUTF16LE(domain), fromUTF16LE(user), fromUTF16LE(ws)
	return a, nil
}

func messageType(ntlm []byte) uint32 {
	if len(ntlm) < 12 {
		return 0
	}
	return binary.LittleEndian.Uint32(ntlm[8:12])
}

// findNTLMSSP locates the NTLMSSP message inside a security blob, which may be
// raw or wrapped in SPNEGO. Searching for the signature avoids implementing an
// ASN.1 parser for a structure whose only interesting part is this.
func findNTLMSSP(blob []byte) []byte {
	idx := indexOfBytes(blob, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil
	}
	return blob[idx:]
}

func indexOfBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

// extractSecurityBuffer pulls the blob out of a SESSION_SETUP request body.
func extractSecurityBuffer(body []byte) []byte {
	if len(body) < 24 {
		return nil
	}
	offset := int(binary.LittleEndian.Uint16(body[12:14]))
	length := int(binary.LittleEndian.Uint16(body[14:16]))
	// Offsets in the request are from the start of the SMB2 header.
	start := offset - 64
	if start < 0 || length <= 0 || start+length > len(body) {
		// Fall back to scanning: a client that lays the buffer out unusually
		// should still get its credentials recorded.
		return body
	}
	return body[start : start+length]
}

func readTreeConnectPath(body []byte) string {
	if len(body) < 8 {
		return ""
	}
	offset := int(binary.LittleEndian.Uint16(body[4:6])) - 64
	length := int(binary.LittleEndian.Uint16(body[6:8]))
	if offset < 0 || length <= 0 || offset+length > len(body) {
		return ""
	}
	path := fromUTF16LE(body[offset : offset+length])
	if i := strings.LastIndex(path, "\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func readCreateName(body []byte) string {
	if len(body) < 60 {
		return ""
	}
	offset := int(binary.LittleEndian.Uint16(body[44:46])) - 64
	length := int(binary.LittleEndian.Uint16(body[46:48]))
	if offset < 0 || length <= 0 || offset+length > len(body) {
		return ""
	}
	return fromUTF16LE(body[offset : offset+length])
}

// --- framing ----------------------------------------------------------------

func readNetBIOS(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length <= 0 || length > 16*1024*1024 {
		return nil, fmt.Errorf("smb: implausible message length %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeNetBIOS(w net.Conn, msg []byte) error {
	hdr := []byte{0x00, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	_, err := w.Write(append(hdr, msg...))
	return err
}

// --- encoding helpers -------------------------------------------------------

func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

func fromUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(units))
}

// windowsTime converts to 100-nanosecond intervals since 1601.
func windowsTime(t time.Time) uint64 {
	const epochDiff = 11644473600
	return uint64((t.Unix() + epochDiff) * 10000000)
}
