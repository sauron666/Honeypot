package honeyd

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/sauron666/Honeypot/internal/event"
)

func TestMySQLCapturesCredentialAndVerifiesPlantedPassword(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "mysql", Persona: "linux/db"})

	conn, err := net.Dial("tcp", addrs["mysql"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)

	_, greeting, err := readMySQLPacket(r)
	if err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if greeting[0] != 10 {
		t.Fatalf("protocol version = %d, want 10", greeting[0])
	}
	salt := extractSalt(t, greeting)

	// "dba123" is one of the planted passwords for linux/db. The decoy must be
	// able to verify it from the scramble alone and let the attacker in.
	if err := writeMySQLPacket(conn, 1, handshakeResponse("dba", "dba123", salt)); err != nil {
		t.Fatal(err)
	}
	_, resp, err := readMySQLPacket(r)
	if err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x00 {
		t.Fatalf("expected an OK packet for a planted password, got 0x%02x", resp[0])
	}

	cred := col.waitFor(t, "mysql credential", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCredentialOffer && e.GetString("auth_method") == "mysql-native-password"
	})
	if v, _ := cred.Get("accepted"); v != true {
		t.Fatal("a correct planted password must be accepted")
	}
	if cred.GetString("secret") != "dba123" {
		t.Fatalf("recovered password = %q, want dba123", cred.GetString("secret"))
	}
	auth := col.waitFor(t, "mysql auth event", func(e *event.Event) bool {
		return e.ClassUID == event.ClassAuthentication
	})
	// Even when we cannot recover the password, the scramble and its salt are
	// what an analyst hands to a cracker; both must be recorded.
	if auth.GetString("auth_salt") == "" || auth.GetString("auth_response_hex") == "" {
		t.Fatalf("crackable material missing: %+v", auth.Data)
	}
}

func TestMySQLRejectsWrongPasswordAndRecordsScramble(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "mysql", Persona: "linux/db"})

	conn, err := net.Dial("tcp", addrs["mysql"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)

	_, greeting, _ := readMySQLPacket(r)
	salt := extractSalt(t, greeting)
	writeMySQLPacket(conn, 1, handshakeResponse("root", "not-the-password", salt))

	_, resp, err := readMySQLPacket(r)
	if err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0xff {
		t.Fatalf("expected an error packet, got 0x%02x", resp[0])
	}
	cred := col.waitFor(t, "rejected mysql credential", func(e *event.Event) bool {
		return e.GetString("auth_method") == "mysql-native-password"
	})
	if v, _ := cred.Get("accepted"); v != false {
		t.Fatal("wrong password recorded as accepted")
	}
	if cred.GetString("secret") != "" {
		t.Fatal("a password we could not recover must not be reported as recovered")
	}
}

func TestMySQLQueriesAreClassified(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "mysql", Persona: "linux/db"})

	conn, err := net.Dial("tcp", addrs["mysql"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)

	_, greeting, _ := readMySQLPacket(r)
	writeMySQLPacket(conn, 1, handshakeResponse("dba", "dba123", extractSalt(t, greeting)))
	readMySQLPacket(r)

	query := func(q string) {
		writeMySQLPacket(conn, 0, append([]byte{0x03}, q...))
		for {
			_, p, err := readMySQLPacket(r)
			if err != nil {
				t.Fatalf("reading answer to %q: %v", q, err)
			}
			// Stop at the terminating EOF or an error packet.
			if p[0] == 0xfe && len(p) < 9 {
				return
			}
			if p[0] == 0xff {
				return
			}
		}
	}
	query("show databases")
	query("select * from mysql.user")
	query("select load_file('/etc/shadow')")

	col.waitFor(t, "credential dump query", func(e *event.Event) bool {
		return e.GetString("finding") == "credential-dump"
	})
	f := col.waitFor(t, "file read via sql", func(e *event.Event) bool {
		return e.GetString("finding") == "sql-file-read"
	})
	if f.SeverityID != event.SeverityCritical {
		t.Fatalf("load_file severity = %s, want critical", f.SeverityID)
	}
}

func extractSalt(t *testing.T, greeting []byte) []byte {
	t.Helper()
	// Greeting layout: 1 version, version string + NUL, 4 conn id, 8 salt, ...
	i := 1
	for i < len(greeting) && greeting[i] != 0 {
		i++
	}
	i++ // NUL
	i += 4
	if i+8 > len(greeting) {
		t.Fatal("greeting too short for salt part 1")
	}
	salt := append([]byte(nil), greeting[i:i+8]...)
	i += 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	if i+12 > len(greeting) {
		t.Fatal("greeting too short for salt part 2")
	}
	return append(salt, greeting[i:i+12]...)
}

func handshakeResponse(user, password string, salt []byte) []byte {
	caps := uint32(capProtocol41 | capSecureConn | capPluginAuth | capLongPassword)
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 16*1024*1024)
	b = append(b, 0xff)
	b = append(b, make([]byte, 23)...)
	b = append(b, user...)
	b = append(b, 0)
	scramble := nativePassword(password, salt)
	b = append(b, byte(len(scramble)))
	b = append(b, scramble...)
	b = append(b, "mysql_native_password"...)
	b = append(b, 0)
	return b
}

func TestMSSQLRecoversPlaintextPassword(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "mssql", Persona: "linux/db"})

	conn, err := net.Dial("tcp", addrs["mssql"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)

	writeTDS(conn, tdsPreLogin, []byte{0xff})
	if _, _, err := readTDS(r); err != nil {
		t.Fatalf("prelogin response: %v", err)
	}

	writeTDS(conn, tdsLogin7, login7("sa", "Sup3rSecret!", "ATTACKER-PC", "sqlcmd"))
	if _, _, err := readTDS(r); err != nil {
		t.Fatalf("login response: %v", err)
	}

	auth := col.waitFor(t, "mssql auth event", func(e *event.Event) bool {
		return e.ClassUID == event.ClassAuthentication && e.Mirage.Service == "mssql"
	})
	// TDS obfuscation is reversible, so the decoy sees the plaintext.
	if auth.GetString("password") != "Sup3rSecret!" {
		t.Fatalf("recovered password = %q, want Sup3rSecret!", auth.GetString("password"))
	}
	if auth.GetString("username") != "sa" {
		t.Fatalf("username = %q", auth.GetString("username"))
	}
	if auth.GetString("client_hostname") != "ATTACKER-PC" {
		t.Fatalf("client hostname = %q; it identifies the attacking machine", auth.GetString("client_hostname"))
	}
}

// login7 builds a minimal LOGIN7 packet body.
func login7(user, password, host, app string) []byte {
	const headerLen = 94
	var data []byte
	offsets := map[string][2]uint16{}

	add := func(name, value string, obfuscate bool) {
		encoded := utf16.Encode([]rune(value))
		raw := make([]byte, 0, len(encoded)*2)
		for _, c := range encoded {
			raw = binary.LittleEndian.AppendUint16(raw, c)
		}
		if obfuscate {
			for i, b := range raw {
				x := b ^ 0xa5
				raw[i] = (x >> 4) | (x << 4)
			}
		}
		offsets[name] = [2]uint16{uint16(headerLen + len(data)), uint16(len(encoded))}
		data = append(data, raw...)
	}
	add("host", host, false)
	add("user", user, false)
	add("pass", password, true)
	add("app", app, false)

	body := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(body[0:], uint32(headerLen+len(data)))
	binary.LittleEndian.PutUint32(body[4:], 0x74000004)
	binary.LittleEndian.PutUint32(body[8:], 4096)
	put := func(pos int, name string) {
		binary.LittleEndian.PutUint16(body[pos:], offsets[name][0])
		binary.LittleEndian.PutUint16(body[pos+2:], offsets[name][1])
	}
	put(36, "host")
	put(40, "user")
	put(44, "pass")
	put(48, "app")
	return append(body, data...)
}

func TestVNCCapturesChallengeResponse(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "vnc"})

	conn, err := net.Dial("tcp", addrs["vnc"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	version := make([]byte, 12)
	if _, err := conn.Read(version); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(version), "RFB 003.008") {
		t.Fatalf("server version = %q", version)
	}
	conn.Write([]byte("RFB 003.008\n"))

	sec := make([]byte, 2)
	conn.Read(sec)
	if sec[0] != 1 || sec[1] != 2 {
		t.Fatalf("expected exactly VNC auth on offer, got %v", sec)
	}
	conn.Write([]byte{2})

	challenge := make([]byte, 16)
	if _, err := conn.Read(challenge); err != nil {
		t.Fatal(err)
	}
	conn.Write(make([]byte, 16)) // a wrong response, as a scanner would send

	e := col.waitFor(t, "vnc auth attempt", func(e *event.Event) bool {
		return e.ClassUID == event.ClassAuthentication && e.Mirage.Service == "vnc"
	})
	if e.GetString("challenge_hex") == "" || e.GetString("response_hex") == "" {
		t.Fatalf("challenge/response not recorded: %+v", e.Data)
	}
}

func TestSMTPCapturesCredentialsAndRefusesToRelay(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "smtp"})

	conn, err := net.Dial("tcp", addrs["smtp"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)

	readLine := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("smtp read: %v", err)
		}
		return line
	}
	if !strings.HasPrefix(readLine(), "220 ") {
		t.Fatal("missing SMTP banner")
	}
	fmt.Fprint(conn, "EHLO attacker.example\r\n")
	for {
		l := readLine()
		if strings.HasPrefix(l, "250 ") {
			break
		}
	}
	// AUTH LOGIN with base64 "spammer" / "hunter2".
	fmt.Fprint(conn, "AUTH LOGIN\r\n")
	readLine()
	fmt.Fprint(conn, "c3BhbW1lcg==\r\n")
	readLine()
	fmt.Fprint(conn, "aHVudGVyMg==\r\n")
	readLine()

	fmt.Fprint(conn, "MAIL FROM:<spoofed@bank.example>\r\n")
	readLine()
	fmt.Fprint(conn, "RCPT TO:<victim@elsewhere.example>\r\n")
	readLine()

	cred := col.waitFor(t, "smtp credential", func(e *event.Event) bool {
		return e.GetString("auth_method") == "smtp-login"
	})
	if cred.GetString("username") != "spammer" || cred.GetString("secret") != "hunter2" {
		t.Fatalf("captured credential = %q/%q", cred.GetString("username"), cred.GetString("secret"))
	}
	relay := col.waitFor(t, "open relay probe", func(e *event.Event) bool {
		return strings.Contains(e.Message, "open relay probe")
	})
	// Containment: the decoy must never actually relay.
	if v, _ := relay.Get("relayed"); v != false {
		t.Fatal("relay event must record that nothing was delivered")
	}
}

func TestSNMPCapturesCommunityString(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "snmp"})

	conn, err := net.Dial("udp", addrs["snmp"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// GetRequest for sysName with community "private".
	if _, err := conn.Write(snmpGetRequestPacket("private", []byte{0x2b, 6, 1, 2, 1, 1, 5, 0})); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("no SNMP answer: %v", err)
	}

	e := col.waitFor(t, "snmp request", func(ev *event.Event) bool {
		return ev.Mirage.Service == "snmp" && ev.GetString("community") != ""
	})
	if e.GetString("community") != "private" {
		t.Fatalf("community = %q, want private", e.GetString("community"))
	}
	if e.GetString("oid") != "1.3.6.1.2.1.1.5.0" {
		t.Fatalf("oid = %q", e.GetString("oid"))
	}
	col.waitFor(t, "snmp community as credential", func(ev *event.Event) bool {
		return ev.ClassUID == event.ClassCredentialOffer && ev.GetString("secret") == "private"
	})
}

func TestSNMPNeverAmplifies(t *testing.T) {
	// A UDP decoy that answers with more bytes than it received is a
	// reflection weapon pointed at whoever the source address claims to be.
	_, col, addrs := startFarm(t, ListenerConfig{Service: "snmp"})

	conn, err := net.Dial("udp", addrs["snmp"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := snmpGetRequestPacket("public", []byte{0x2b, 6, 1, 2, 1, 1, 1, 0}) // sysDescr
	conn.Write(req)

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err == nil {
		// The reply may be marginally longer than the question, but never by
		// enough to be worth reflecting at a spoofed victim.
		if !amplificationSafe(len(req), n) {
			t.Fatalf("decoy amplified: %d byte request produced a %d byte reply", len(req), n)
		}
		if float64(n)/float64(len(req)) > 3 {
			t.Fatalf("amplification factor %.1fx is too high", float64(n)/float64(len(req)))
		}
		return
	}
	// A withheld answer must be recorded rather than silently dropped.
	col.waitFor(t, "amplification guard event", func(e *event.Event) bool {
		return e.ClassUID == event.ClassContainment
	})
}

func snmpGetRequestPacket(community string, oid []byte) []byte {
	varbind := berTLV(0x30, append(berTLV(0x06, oid), berTLV(0x05, nil)...))
	pdu := berTLV(0x02, []byte{0x12, 0x34})
	pdu = append(pdu, berTLV(0x02, []byte{0})...)
	pdu = append(pdu, berTLV(0x02, []byte{0})...)
	pdu = append(pdu, berTLV(0x30, varbind)...)

	body := berTLV(0x02, []byte{1}) // v2c
	body = append(body, berTLV(0x04, []byte(community))...)
	body = append(body, berTLV(snmpGetRequest, pdu)...)
	return berTLV(0x30, body)
}

func TestModbusReadsAreReconAndWritesAreCritical(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "modbus"})

	conn, err := net.Dial("tcp", addrs["modbus"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	send := func(unit byte, pdu []byte) []byte {
		frame := make([]byte, 7+len(pdu))
		binary.BigEndian.PutUint16(frame[0:], 1)
		binary.BigEndian.PutUint16(frame[2:], 0)
		binary.BigEndian.PutUint16(frame[4:], uint16(len(pdu)+1))
		frame[6] = unit
		copy(frame[7:], pdu)
		if _, err := conn.Write(frame); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, 512)
		n, err := conn.Read(resp)
		if err != nil {
			t.Fatalf("modbus read: %v", err)
		}
		return resp[:n]
	}

	// Read ten holding registers: reconnaissance.
	readPDU := []byte{fcReadHoldingRegisters, 0x00, 0x00, 0x00, 0x0a}
	resp := send(1, readPDU)
	if len(resp) < 9 || resp[7] != fcReadHoldingRegisters {
		t.Fatalf("unexpected read response: %v", resp)
	}
	readEv := col.waitFor(t, "modbus read", func(e *event.Event) bool {
		return e.GetString("function") == "read holding registers"
	})
	if readEv.SeverityID > event.SeverityMedium {
		t.Fatalf("a register read should not be critical, got %s", readEv.SeverityID)
	}

	// Write a register: an attempt to change a physical process.
	writePDU := []byte{fcWriteSingleRegister, 0x00, 0x05, 0x13, 0x88}
	send(1, writePDU)
	w := col.waitFor(t, "modbus write", func(e *event.Event) bool {
		return e.GetString("function") == "write single register"
	})
	if w.SeverityID != event.SeverityCritical {
		t.Fatalf("a PLC write must be critical, got %s", w.SeverityID)
	}
	if !hasTechnique(w, "T0836") {
		t.Fatalf("PLC write not mapped to the ICS matrix: %+v", w.Mirage.Attack)
	}

	// Reading it back must show the value the attacker wrote, or the decoy
	// looks broken the moment they verify their own action.
	resp = send(1, []byte{fcReadHoldingRegisters, 0x00, 0x05, 0x00, 0x01})
	if len(resp) >= 11 {
		if got := binary.BigEndian.Uint16(resp[9:11]); got != 0x1388 {
			t.Fatalf("register read back as 0x%04x, want 0x1388", got)
		}
	}
}
