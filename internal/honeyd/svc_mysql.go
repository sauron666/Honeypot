package honeyd

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("mysql", newMySQL) }

// mysqlSvc speaks the real MySQL wire protocol.
//
// It is worth implementing properly rather than emulating with a banner: the
// client's authentication response is a SHA-1 challenge-response over a salt we
// chose, which means the capture is offline-crackable evidence of exactly which
// password an attacker tried. We can also verify a guess ourselves, so a decoy
// can let an attacker in when they guess a planted credential.
type mysqlSvc struct {
	p       *Persona
	version string
}

func newMySQL(p *Persona, opts map[string]any) (Service, error) {
	m := &mysqlSvc{p: p, version: "8.0.36-0ubuntu0.22.04.1"}
	if v, ok := opts["version"].(string); ok && v != "" {
		m.version = v
	}
	return m, nil
}

func (m *mysqlSvc) Type() string { return "mysql" }

// MySQL capability flags we advertise.
const (
	capLongPassword     = 0x00000001
	capFoundRows        = 0x00000002
	capLongFlag         = 0x00000004
	capConnectWithDB    = 0x00000008
	capProtocol41       = 0x00000200
	capSecureConn       = 0x00008000
	capPluginAuth       = 0x00080000
	capConnAttrs        = 0x00100000
	capPluginAuthLenEnc = 0x00200000
	capDeprecateEOF     = 0x01000000
)

func (m *mysqlSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)

	salt := make([]byte, 20)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	for i := range salt { // the salt is a printable string on the wire
		salt[i] = 0x21 + salt[i]%0x5d
	}

	if err := writeMySQLPacket(conn, 0, m.handshake(salt)); err != nil {
		return err
	}

	seq, payload, err := readMySQLPacket(r)
	if err != nil {
		return fmt.Errorf("handshake response: %w", err)
	}
	s.Record("in", payload)

	user, authResp, db, clientCaps := parseHandshakeResponse(payload)
	accepted, matched := m.verify(user, authResp, salt)

	cred := Credential{
		Username: user, Method: "mysql-native-password", Accepted: accepted,
		// The scramble plus the salt is what an analyst hands to a cracker.
		KeyType:  "mysql-scramble",
		KeyPrint: hex.EncodeToString(authResp),
	}
	if matched != "" {
		cred.Secret = matched
	}
	s.AddCredential(cred)

	e := s.Event(event.ClassAuthentication, 1, event.SeverityMedium).
		WithMessage("MySQL login attempt for %q on database %q", user, db).
		WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1110", Name: "Brute Force"})
	e.Set("username", user).Set("database", db).
		Set("client_capabilities", fmt.Sprintf("0x%08x", clientCaps)).
		Set("auth_salt", string(salt[:20])).
		Set("auth_response_hex", hex.EncodeToString(authResp)).
		Set("crackable", "mysql_native_password: sha1 challenge-response over auth_salt").
		Set("accepted", accepted)
	s.Emit(e)

	if !accepted {
		return writeMySQLPacket(conn, seq+1, mysqlErr(1045,
			fmt.Sprintf("Access denied for user '%s'@'%s' (using password: YES)", user, s.SrcIP())))
	}
	if err := writeMySQLPacket(conn, seq+1, mysqlOK()); err != nil {
		return err
	}
	s.Note(event.SeverityHigh, "MySQL login accepted for %q", user)
	return m.commandLoop(ctx, conn, r, s, user)
}

// verify checks the client's scramble against the persona's planted passwords.
// mysql_native_password is XOR(SHA1(pw), SHA1(salt || SHA1(SHA1(pw)))), which we
// can recompute for each candidate.
func (m *mysqlSvc) verify(user string, authResp, salt []byte) (bool, string) {
	if len(authResp) != 20 {
		return len(authResp) == 0 && m.p.Accepts(user, ""), ""
	}
	candidates := append([]string{}, m.p.WeakSecrets[user]...)
	candidates = append(candidates, m.p.WeakSecrets["*"]...)
	for _, pw := range candidates {
		if equalBytes(nativePassword(pw, salt[:20]), authResp) {
			return true, pw
		}
	}
	return false, ""
}

func nativePassword(password string, salt []byte) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(h2[:])
	scr := h.Sum(nil)
	out := make([]byte, len(scr))
	for i := range scr {
		out[i] = scr[i] ^ h1[i]
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (m *mysqlSvc) handshake(salt []byte) []byte {
	caps := uint32(capLongPassword | capFoundRows | capLongFlag | capConnectWithDB |
		capProtocol41 | capSecureConn | capPluginAuth | capConnAttrs | capPluginAuthLenEnc)

	var b []byte
	b = append(b, 10) // protocol version
	b = append(b, []byte(m.version)...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0x00000c1f) // connection id
	b = append(b, salt[:8]...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(caps))
	b = append(b, 0xff) // utf8mb4
	b = binary.LittleEndian.AppendUint16(b, 0x0002)
	b = binary.LittleEndian.AppendUint16(b, uint16(caps>>16))
	b = append(b, 21) // auth plugin data length
	b = append(b, make([]byte, 10)...)
	b = append(b, salt[8:20]...)
	b = append(b, 0)
	b = append(b, []byte("mysql_native_password")...)
	b = append(b, 0)
	return b
}

func parseHandshakeResponse(p []byte) (user string, authResp []byte, db string, caps uint32) {
	if len(p) < 33 {
		return "", nil, "", 0
	}
	caps = binary.LittleEndian.Uint32(p[0:4])
	pos := 32
	end := indexByte(p[pos:], 0)
	if end < 0 {
		return "", nil, "", caps
	}
	user = string(p[pos : pos+end])
	pos += end + 1

	if pos >= len(p) {
		return user, nil, "", caps
	}
	if caps&capPluginAuthLenEnc != 0 {
		n, adv := lenEncInt(p[pos:])
		pos += adv
		if pos+int(n) <= len(p) {
			authResp = p[pos : pos+int(n)]
			pos += int(n)
		}
	} else {
		n := int(p[pos])
		pos++
		if pos+n <= len(p) {
			authResp = p[pos : pos+n]
			pos += n
		}
	}
	if caps&capConnectWithDB != 0 && pos < len(p) {
		if end := indexByte(p[pos:], 0); end >= 0 {
			db = string(p[pos : pos+end])
		}
	}
	return user, authResp, db, caps
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func lenEncInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch {
	case b[0] < 0xfb:
		return uint64(b[0]), 1
	case b[0] == 0xfc && len(b) >= 3:
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3
	case b[0] == 0xfd && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	case b[0] == 0xfe && len(b) >= 9:
		return binary.LittleEndian.Uint64(b[1:9]), 9
	default:
		return 0, 1
	}
}

// commandLoop answers queries after a successful login.
func (m *mysqlSvc) commandLoop(ctx context.Context, conn net.Conn, r *bufio.Reader, s *Session, user string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		seq, payload, err := readMySQLPacket(r)
		if err != nil {
			return nil
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case 0x01: // COM_QUIT
			return nil
		case 0x03: // COM_QUERY
			query := string(payload[1:])
			s.Record("in", []byte(query))
			m.recordQuery(query, s)
			if err := m.answer(conn, seq+1, query); err != nil {
				return err
			}
		case 0x0e: // COM_PING
			if err := writeMySQLPacket(conn, seq+1, mysqlOK()); err != nil {
				return err
			}
		case 0x02: // COM_INIT_DB
			if err := writeMySQLPacket(conn, seq+1, mysqlOK()); err != nil {
				return err
			}
		default:
			if err := writeMySQLPacket(conn, seq+1, mysqlErr(1047, "Unknown command")); err != nil {
				return err
			}
		}
	}
}

// recordQuery classifies SQL. The queries an attacker runs against a database
// say plainly what they came for.
func (m *mysqlSvc) recordQuery(q string, s *Session) {
	l := strings.ToLower(q)
	sev := event.SeverityMedium
	var techniques []event.Technique
	var finding string

	switch {
	case strings.Contains(l, "into outfile"), strings.Contains(l, "into dumpfile"):
		sev, finding = event.SeverityCritical, "sql-file-write"
		techniques = append(techniques, event.Technique{Tactic: "TA0002", Technique: "T1505", Name: "Server Software Component"})
	case strings.Contains(l, "load_file("), strings.Contains(l, "load data infile"):
		sev, finding = event.SeverityCritical, "sql-file-read"
		techniques = append(techniques, event.Technique{Tactic: "TA0009", Technique: "T1005", Name: "Data from Local System"})
	case strings.Contains(l, "sys_exec"), strings.Contains(l, "create function"), strings.Contains(l, "lib_mysqludf"):
		sev, finding = event.SeverityCritical, "udf-rce"
		techniques = append(techniques, event.Technique{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"})
	case strings.Contains(l, "mysql.user"), strings.Contains(l, "authentication_string"), strings.Contains(l, "password"):
		sev, finding = event.SeverityHigh, "credential-dump"
		techniques = append(techniques, event.Technique{Tactic: "TA0006", Technique: "T1555", Name: "Credentials from Password Stores"})
	case strings.Contains(l, "information_schema"), strings.HasPrefix(l, "show "):
		sev, finding = event.SeverityLow, "schema-discovery"
		techniques = append(techniques, event.Technique{Tactic: "TA0007", Technique: "T1082", Name: "System Information Discovery"})
	case strings.HasPrefix(l, "select"):
		sev, finding = event.SeverityMedium, "data-access"
		techniques = append(techniques, event.Technique{Tactic: "TA0009", Technique: "T1213", Name: "Data from Information Repositories"})
	}

	s.Command("mysql: "+q, sev, techniques...)
	if finding != "" && sev >= event.SeverityHigh {
		e := s.Event(event.ClassDetectionFinding, 1, sev).
			WithMessage("MySQL %s: %s", finding, truncate(q, 300)).
			WithAttack(techniques...)
		e.Set("query", truncate(q, 8192)).Set("finding", finding)
		s.Emit(e)
	}
}

func (m *mysqlSvc) answer(conn net.Conn, seq uint8, query string) error {
	l := strings.ToLower(strings.TrimSpace(query))
	switch {
	case strings.HasPrefix(l, "show databases"):
		return m.resultSet(conn, seq, []string{"Database"},
			[][]string{{"information_schema"}, {"billing"}, {"crm"}, {"mysql"}, {"performance_schema"}, {"sys"}})
	case strings.HasPrefix(l, "show tables"):
		return m.resultSet(conn, seq, []string{"Tables_in_billing"},
			[][]string{{"invoices"}, {"customers"}, {"payments"}, {"users"}, {"audit_log"}})
	case strings.Contains(l, "@@version"), strings.HasPrefix(l, "select version()"):
		return m.resultSet(conn, seq, []string{"@@version"}, [][]string{{m.version}})
	case strings.Contains(l, "user()"), strings.Contains(l, "current_user"):
		return m.resultSet(conn, seq, []string{"user()"}, [][]string{{"root@localhost"}})
	case strings.Contains(l, "database()"):
		return m.resultSet(conn, seq, []string{"database()"}, [][]string{{"billing"}})
	case strings.Contains(l, "mysql.user"):
		// Answering the credential dump with plausible hashes keeps the
		// attacker engaged, and every one of them is bait.
		return m.resultSet(conn, seq, []string{"user", "host", "authentication_string"}, [][]string{
			{"root", "localhost", "*" + strings.ToUpper(m.p.RandomToken(40))},
			{"billing_app", "%", "*" + strings.ToUpper(m.p.RandomToken(40))},
			{"backup", "10.10.%", "*" + strings.ToUpper(m.p.RandomToken(40))},
		})
	default:
		return writeMySQLPacket(conn, seq, mysqlErr(1142,
			"SELECT command denied to user for this operation"))
	}
}

// resultSet writes a complete text protocol result set.
func (m *mysqlSvc) resultSet(conn net.Conn, seq uint8, columns []string, rows [][]string) error {
	if err := writeMySQLPacket(conn, seq, []byte{byte(len(columns))}); err != nil {
		return err
	}
	seq++
	for _, c := range columns {
		if err := writeMySQLPacket(conn, seq, columnDef(c)); err != nil {
			return err
		}
		seq++
	}
	if err := writeMySQLPacket(conn, seq, mysqlEOF()); err != nil {
		return err
	}
	seq++
	for _, row := range rows {
		var b []byte
		for _, v := range row {
			b = appendLenEncString(b, v)
		}
		if err := writeMySQLPacket(conn, seq, b); err != nil {
			return err
		}
		seq++
	}
	return writeMySQLPacket(conn, seq, mysqlEOF())
}

func columnDef(name string) []byte {
	var b []byte
	b = appendLenEncString(b, "def")
	b = appendLenEncString(b, "billing")
	b = appendLenEncString(b, "t")
	b = appendLenEncString(b, "t")
	b = appendLenEncString(b, name)
	b = appendLenEncString(b, name)
	b = append(b, 0x0c)
	b = binary.LittleEndian.AppendUint16(b, 0x00ff) // charset utf8mb4
	b = binary.LittleEndian.AppendUint32(b, 1024)   // column length
	b = append(b, 0xfd)                             // MYSQL_TYPE_VAR_STRING
	b = binary.LittleEndian.AppendUint16(b, 0)      // flags
	b = append(b, 0, 0, 0)                          // decimals + filler
	return b
}

func appendLenEncString(b []byte, s string) []byte {
	n := len(s)
	switch {
	case n < 251:
		b = append(b, byte(n))
	case n < 1<<16:
		b = append(b, 0xfc)
		b = binary.LittleEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 0xfd, byte(n), byte(n>>8), byte(n>>16))
	}
	return append(b, s...)
}

func mysqlOK() []byte {
	b := []byte{0x00, 0x00, 0x00}
	b = binary.LittleEndian.AppendUint16(b, 0x0002)
	return binary.LittleEndian.AppendUint16(b, 0)
}

func mysqlEOF() []byte {
	b := []byte{0xfe}
	b = binary.LittleEndian.AppendUint16(b, 0)
	return binary.LittleEndian.AppendUint16(b, 0x0002)
}

func mysqlErr(code uint16, msg string) []byte {
	b := []byte{0xff}
	b = binary.LittleEndian.AppendUint16(b, code)
	b = append(b, '#')
	b = append(b, []byte("28000")...)
	return append(b, msg...)
}

func writeMySQLPacket(w io.Writer, seq uint8, payload []byte) error {
	n := len(payload)
	hdr := []byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
	if _, err := w.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

func readMySQLPacket(r *bufio.Reader) (uint8, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n > 16*1024*1024 {
		return 0, nil, fmt.Errorf("mysql: packet of %d bytes is implausible", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}
