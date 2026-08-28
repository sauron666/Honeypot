package honeyd

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode/utf16"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("mssql", newMSSQL) }

// mssqlSvc speaks enough TDS to complete a login attempt.
//
// TDS "encrypts" the password in LOGIN7 with a nibble swap and an XOR against
// 0xA5. That is not encryption, it is obfuscation, and it means a decoy sees
// the attacker's password in plaintext -- no cracking required. For a Windows
// estate that is among the most valuable things a honeypot can produce.
type mssqlSvc struct {
	p       *Persona
	version string
}

func newMSSQL(p *Persona, opts map[string]any) (Service, error) {
	m := &mssqlSvc{p: p, version: "15.0.4335.1"}
	if v, ok := opts["version"].(string); ok && v != "" {
		m.version = v
	}
	return m, nil
}

func (m *mssqlSvc) Type() string { return "mssql" }

// TDS packet types.
const (
	tdsSQLBatch = 0x01
	tdsLogin7   = 0x10
	tdsPreLogin = 0x12
	tdsResponse = 0x04
)

func (m *mssqlSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		typ, payload, err := readTDS(r)
		if err != nil {
			return nil
		}
		s.Record("in", payload)

		switch typ {
		case tdsPreLogin:
			if err := writeTDS(conn, tdsResponse, m.preLoginResponse()); err != nil {
				return err
			}

		case tdsLogin7:
			user, pass, host, app, db := parseLogin7(payload)
			accepted := m.p.Accepts(user, pass, 1)
			s.AddCredential(Credential{
				Username: user, Secret: pass, Method: "mssql-sql-auth", Accepted: accepted,
			})

			e := s.Event(event.ClassAuthentication, 1, event.SeverityHigh).
				WithMessage("MSSQL login attempt for %q from host %q via %q", user, host, app).
				WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1110", Name: "Brute Force"})
			e.Set("username", user).Set("password", pass).Set("client_hostname", host).
				Set("application", app).Set("database", db).Set("accepted", accepted).
				Set("note", "TDS obfuscates passwords with a nibble swap and XOR 0xA5; this is the plaintext")
			s.Emit(e)

			if !accepted {
				return writeTDS(conn, tdsResponse, tdsError(18456,
					fmt.Sprintf("Login failed for user '%s'.", user)))
			}
			s.Note(event.SeverityHigh, "MSSQL login accepted for %q", user)
			if err := writeTDS(conn, tdsResponse, m.loginAck()); err != nil {
				return err
			}

		case tdsSQLBatch:
			query := decodeUCS2(payload)
			s.Command("mssql: "+query, event.SeverityHigh,
				event.Technique{Tactic: "TA0009", Technique: "T1213", Name: "Data from Information Repositories"})
			// xp_cmdshell is the reason attackers want MSSQL at all.
			if containsAny(strings.ToLower(query), "xp_cmdshell", "sp_configure", "openrowset", "sp_oacreate") {
				e := s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
					WithMessage("MSSQL command execution attempt: %s", truncate(query, 300)).
					WithAttack(event.Technique{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"})
				e.Set("query", truncate(query, 8192))
				s.Emit(e)
			}
			if err := writeTDS(conn, tdsResponse, tdsError(229,
				"The EXECUTE permission was denied on the object.")); err != nil {
				return err
			}

		default:
			return nil
		}
	}
}

func (m *mssqlSvc) preLoginResponse() []byte {
	// Option tokens: VERSION(0), ENCRYPTION(1), INSTOPT(2), THREADID(3), terminator.
	body := []byte{
		0x00, 0x00, 0x1a, 0x00, 0x06, // VERSION at 0x1a len 6
		0x01, 0x00, 0x20, 0x00, 0x01, // ENCRYPTION at 0x20 len 1
		0x02, 0x00, 0x21, 0x00, 0x01, // INSTOPT at 0x21 len 1
		0x03, 0x00, 0x22, 0x00, 0x04, // THREADID at 0x22 len 4
		0xff,
	}
	body = append(body, 15, 0, 0, 0, 0, 0) // version 15.0 (SQL Server 2019)
	body = append(body, 0x02)              // encryption not supported
	body = append(body, 0x00)              // instance name terminator
	body = append(body, 0, 0, 0, 0)        // thread id
	return body
}

func (m *mssqlSvc) loginAck() []byte {
	name := utf16.Encode([]rune("Microsoft SQL Server"))
	var body []byte
	body = append(body, 0xad) // LOGINACK token
	inner := []byte{0x01}     // interface
	inner = append(inner, 0x74, 0x00, 0x00, 0x04)
	inner = append(inner, byte(len(name)))
	for _, c := range name {
		inner = binary.LittleEndian.AppendUint16(inner, c)
	}
	inner = append(inner, 15, 0, 0x10, 0xef) // server version
	body = binary.LittleEndian.AppendUint16(body, uint16(len(inner)))
	body = append(body, inner...)
	body = append(body, 0xfd, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0) // DONE
	return body
}

func tdsError(number uint32, msg string) []byte {
	text := utf16.Encode([]rune(msg))
	server := utf16.Encode([]rune("SQLSRV"))

	var inner []byte
	inner = binary.LittleEndian.AppendUint32(inner, number)
	inner = append(inner, 1, 14) // state, class
	inner = binary.LittleEndian.AppendUint16(inner, uint16(len(text)))
	for _, c := range text {
		inner = binary.LittleEndian.AppendUint16(inner, c)
	}
	inner = append(inner, byte(len(server)))
	for _, c := range server {
		inner = binary.LittleEndian.AppendUint16(inner, c)
	}
	inner = append(inner, 0)                           // procedure name length
	inner = binary.LittleEndian.AppendUint32(inner, 1) // line number

	var body []byte
	body = append(body, 0xaa) // ERROR token
	body = binary.LittleEndian.AppendUint16(body, uint16(len(inner)))
	body = append(body, inner...)
	body = append(body, 0xfd, 0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0) // DONE with error
	return body
}

// parseLogin7 extracts the interesting fields of a LOGIN7 packet.
func parseLogin7(p []byte) (user, pass, host, app, db string) {
	if len(p) < 94 {
		return
	}
	str := func(offPos int) string {
		if offPos+4 > len(p) {
			return ""
		}
		off := int(binary.LittleEndian.Uint16(p[offPos:]))
		n := int(binary.LittleEndian.Uint16(p[offPos+2:])) * 2
		if off < 0 || n < 0 || off+n > len(p) {
			return ""
		}
		return decodeUCS2(p[off : off+n])
	}
	host = str(36)
	user = str(40)

	// The password field needs de-obfuscating before it is text.
	if 48 <= len(p) {
		off := int(binary.LittleEndian.Uint16(p[44:]))
		n := int(binary.LittleEndian.Uint16(p[46:])) * 2
		if off >= 0 && n >= 0 && off+n <= len(p) {
			pass = decodeUCS2(deobfuscateTDSPassword(p[off : off+n]))
		}
	}
	app = str(48)
	db = str(60)
	return
}

// deobfuscateTDSPassword reverses TDS password "encryption": swap the nibbles
// of each byte, then XOR with 0xA5.
func deobfuscateTDSPassword(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = ((b >> 4) | (b << 4)) ^ 0xa5
	}
	return out
}

func decodeUCS2(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(units))
}

func readTDS(r *bufio.Reader) (byte, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 8 || length > 1<<20 {
		return 0, nil, fmt.Errorf("mssql: implausible packet length %d", length)
	}
	body := make([]byte, length-8)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

func writeTDS(w net.Conn, typ byte, body []byte) error {
	hdr := make([]byte, 8)
	hdr[0] = typ
	hdr[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(body)+8))
	hdr[6] = 1
	_, err := w.Write(append(hdr, body...))
	return err
}
