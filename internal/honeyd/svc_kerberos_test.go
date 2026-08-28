package honeyd

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// --- a small Kerberos client, the way GetNPUsers or Rubeus would speak -------

type krbClient struct {
	t    *testing.T
	addr string
}

// ask sends one KDC request over TCP and returns the reply.
func (c *krbClient) ask(msg []byte) []byte {
	c.t.Helper()
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		c.t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(msg)))
	if _, err := conn.Write(append(l[:], msg...)); err != nil {
		c.t.Fatal(err)
	}
	var rl [4]byte
	if _, err := io.ReadFull(conn, rl[:]); err != nil {
		c.t.Fatalf("no reply from the KDC: %v", err)
	}
	size := binary.BigEndian.Uint32(rl[:])
	if size == 0 || size > 1<<20 {
		c.t.Fatalf("implausible reply length %d", size)
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(conn, out); err != nil {
		c.t.Fatal(err)
	}
	return out
}

// asReq builds an AS-REQ. padata is optional PA-ENC-TIMESTAMP material.
func asReq(client, realm, service string, etypes []int, padata []byte) []byte {
	var pa []byte
	if padata != nil {
		entry := derSequence(append(
			derCtx(1, berInteger(paEncTimestamp)),
			derCtx(2, derOctetString(derEncryptedData(etypeRC4HMAC, 0, padata)))...))
		pa = derCtx(3, derSequence(entry))
	}

	var et []byte
	for _, e := range etypes {
		et = append(et, berInteger(e)...)
	}
	body := derCtx(0, derBitString([]byte{0x40, 0x81, 0x00, 0x10}))
	body = append(body, derCtx(1, derPrincipalName(ntPrincipal, client))...)
	body = append(body, derCtx(2, derGeneralString(realm))...)
	body = append(body, derCtx(3, derPrincipalName(ntSrvInst, strings.Split(service, "/")...))...)
	body = append(body, derCtx(5, derKerberosTime(time.Now().Add(10*time.Hour)))...)
	body = append(body, derCtx(7, berInteger(1234567))...)
	body = append(body, derCtx(8, derSequence(et))...)

	msg := derCtx(1, berInteger(5))
	msg = append(msg, derCtx(2, berInteger(krbASReq))...)
	msg = append(msg, pa...)
	msg = append(msg, derCtx(4, derSequence(body))...)
	return derApp(krbASReq, derSequence(msg))
}

// tgsReq builds a TGS-REQ for one SPN, which is what a kerberoast is.
func tgsReq(client, realm, spn string, etypes []int) []byte {
	var et []byte
	for _, e := range etypes {
		et = append(et, berInteger(e)...)
	}
	body := derCtx(0, derBitString([]byte{0x40, 0x81, 0x00, 0x00}))
	body = append(body, derCtx(1, derPrincipalName(ntPrincipal, client))...)
	body = append(body, derCtx(2, derGeneralString(realm))...)
	body = append(body, derCtx(3, derPrincipalName(ntSrvInst, strings.Split(spn, "/")...))...)
	body = append(body, derCtx(5, derKerberosTime(time.Now().Add(10*time.Hour)))...)
	body = append(body, derCtx(7, berInteger(7654321))...)
	body = append(body, derCtx(8, derSequence(et))...)

	// A real TGS-REQ carries the TGT in PA-TGS-REQ. The decoy does not verify
	// it -- it cannot, the ticket it issued is not real -- but a request
	// without one would not look like a kerberoast.
	pa := derCtx(3, derSequence(derSequence(append(
		derCtx(1, berInteger(paTGSReq)),
		derCtx(2, derOctetString([]byte{0x6e, 0x02, 0x30, 0x00}))...))))

	msg := derCtx(1, berInteger(5))
	msg = append(msg, derCtx(2, berInteger(krbTGSReq))...)
	msg = append(msg, pa...)
	msg = append(msg, derCtx(4, derSequence(body))...)
	return derApp(krbTGSReq, derSequence(msg))
}

// krbErrorCode reads the error-code out of a KRB-ERROR, or -1 if this is not one.
func krbErrorCode(t *testing.T, reply []byte) int {
	t.Helper()
	tag, body, _, err := berNext(reply)
	if err != nil || tag != 0x60|krbErrorMsg {
		return -1
	}
	seqTag, seq, _, err := berNext(body)
	if err != nil || seqTag != 0x30 {
		return -1
	}
	rest := seq
	for len(rest) > 0 {
		var ct byte
		var v []byte
		ct, v, rest, err = berNext(rest)
		if err != nil {
			return -1
		}
		if ct == 0xa6 {
			if n, ok := derInt(v); ok {
				return n
			}
		}
	}
	return -1
}

// replyAppTag reports the application tag of a reply, so a test can tell an
// AS-REP from an error without decoding the whole message.
func replyAppTag(reply []byte) byte {
	if len(reply) == 0 {
		return 0
	}
	return reply[0] & 0x1f
}

func startKDC(t *testing.T) (*collector, *krbClient) {
	t.Helper()
	_, col, addrs := startFarm(t, ListenerConfig{
		Service: "kerberos", Persona: "windows/dc", DecoyID: "dcy-dc01", Protocol: "tcp"})
	return col, &krbClient{t: t, addr: addrs["kerberos"]}
}

// --- tests -------------------------------------------------------------------

func TestKerberosDistinguishesKnownFromUnknownUsers(t *testing.T) {
	// This is the whole of username enumeration, and a decoy that got it wrong
	// in either direction would be spotted immediately: answering
	// PREAUTH_REQUIRED for everything claims a domain where every name exists.
	col, c := startKDC(t)

	reply := c.ask(asReq("nosuchuser", "CORP.LOCAL", "krbtgt/CORP.LOCAL",
		[]int{etypeRC4HMAC}, nil))
	if got := krbErrorCode(t, reply); got != kdcErrPrincipalUnknown {
		t.Fatalf("unknown user got error %d, want KDC_ERR_C_PRINCIPAL_UNKNOWN (%d)",
			got, kdcErrPrincipalUnknown)
	}

	reply = c.ask(asReq("m.petrova", "CORP.LOCAL", "krbtgt/CORP.LOCAL",
		[]int{etypeRC4HMAC}, nil))
	if got := krbErrorCode(t, reply); got != kdcErrPreauthRequired {
		t.Fatalf("known user got error %d, want KDC_ERR_PREAUTH_REQUIRED (%d)",
			got, kdcErrPreauthRequired)
	}

	// Both halves have to be recorded: the misses are the attacker's wordlist.
	col.waitFor(t, "the enumeration miss", hasData("kdc_error", "KDC_ERR_C_PRINCIPAL_UNKNOWN"))
	hit := col.waitFor(t, "the enumeration hit", hasData("kdc_error", "KDC_ERR_PREAUTH_REQUIRED"))
	if hit.GetString("principal") != "m.petrova" {
		t.Fatalf("the discovered account was not named: %+v", hit.Message)
	}
}

func TestASREPRoastYieldsAHashThatCracksToThePlantedPassword(t *testing.T) {
	// The bait only works if the crack succeeds. A blob an attacker's hashcat
	// run cannot break tells them the account is not real.
	col, c := startKDC(t)

	reply := c.ask(asReq("svc_legacy", "CORP.LOCAL", "krbtgt/CORP.LOCAL",
		[]int{etypeRC4HMAC}, nil))
	if tag := replyAppTag(reply); tag != krbASRep {
		t.Fatalf("an account with pre-auth disabled did not produce an AS-REP "+
			"(application tag %d, error %d)", tag, krbErrorCode(t, reply))
	}

	e := col.waitFor(t, "the AS-REP roast", func(e *event.Event) bool {
		return strings.Contains(e.Message, "AS-REP roast")
	})
	if e.SeverityID < event.SeverityHigh {
		t.Fatalf("an AS-REP roast was recorded at severity %d", e.SeverityID)
	}
	hash := e.GetString("asrep_hash")
	password := e.GetString("planted_password")
	if hash == "" || password == "" {
		t.Fatalf("the roast recorded neither the hash nor what it cracks to: %s", e.Message)
	}
	if !strings.HasPrefix(hash, "$krb5asrep$23$svc_legacy@CORP.LOCAL:") {
		t.Fatalf("the hash is not in the form hashcat mode 18200 reads: %q", hash)
	}

	// Now do what the attacker does: take the hash, try the password, and see
	// the plaintext come back. If this fails, so does their crack, and the
	// bait is worthless.
	if !crackASREP(t, hash, password) {
		t.Fatal("the recorded hash does not actually decrypt under the planted password")
	}
}

func TestKerberoastYieldsACrackableServiceTicket(t *testing.T) {
	col, c := startKDC(t)

	reply := c.ask(tgsReq("m.petrova", "CORP.LOCAL", "MSSQLSvc/sql01.corp.local:1433",
		[]int{etypeRC4HMAC}))
	if tag := replyAppTag(reply); tag != krbTGSRep {
		t.Fatalf("a kerberoast did not produce a TGS-REP (tag %d, error %d)",
			tag, krbErrorCode(t, reply))
	}

	e := col.waitFor(t, "the kerberoast", func(e *event.Event) bool {
		return strings.Contains(e.Message, "kerberoast")
	})
	if e.SeverityID != event.SeverityCritical {
		t.Fatalf("an RC4-first kerberoast was recorded at severity %d, want critical", e.SeverityID)
	}
	hash := e.GetString("tgs_hash")
	if !strings.HasPrefix(hash, "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$") {
		t.Fatalf("the hash is not in the form hashcat mode 13100 reads: %q", hash)
	}
	if !crackTGS(t, hash, e.GetString("planted_password")) {
		t.Fatal("the recorded ticket does not decrypt under the planted password")
	}
	if !hasTechnique(e, "T1558.003") {
		t.Fatal("a kerberoast was not mapped to T1558.003")
	}
}

func TestKerberosRecordsAWrongPasswordAsAGuess(t *testing.T) {
	// A spray is only distinguishable from noise if the KDC actually checks the
	// password rather than rejecting everything.
	col, c := startKDC(t)

	wrong, err := rc4Encrypt(ntHash("Autumn2021!"), krbUsagePAEncTimestamp,
		make([]byte, 8), paTimestamp())
	if err != nil {
		t.Fatal(err)
	}
	reply := c.ask(asReq("m.petrova", "CORP.LOCAL", "krbtgt/CORP.LOCAL",
		[]int{etypeRC4HMAC}, wrong))
	if got := krbErrorCode(t, reply); got != kdcErrPreauthFailed {
		t.Fatalf("a wrong password got error %d, want KDC_ERR_PREAUTH_FAILED (%d)",
			got, kdcErrPreauthFailed)
	}

	e := col.waitFor(t, "the failed guess", hasData("kdc_error", "KDC_ERR_PREAUTH_FAILED"))
	if !hasTechnique(e, "T1110.003") {
		t.Fatal("a Kerberos password guess was not mapped to password spraying")
	}
}

func TestKerberosAcceptsThePlantedPasswordAndSaysSo(t *testing.T) {
	// When the guess is right, the credential has to be recorded as accepted:
	// that is what lets the honeytoken watcher join this moment to the next
	// place the same password turns up.
	col, c := startKDC(t)

	// Learn the planted password the way the roast would hand it over.
	p, err := BuildPersona("windows/dc", "test-seed-fixed")
	if err != nil {
		t.Fatal(err)
	}
	dir := buildHoneyDirectory(p)
	acct, ok := dir.Account("m.petrova")
	if !ok {
		t.Fatal("the persona has no m.petrova")
	}

	good, err := rc4Encrypt(ntHash(acct.Password), krbUsagePAEncTimestamp,
		make([]byte, 8), paTimestamp())
	if err != nil {
		t.Fatal(err)
	}
	reply := c.ask(asReq("m.petrova", "CORP.LOCAL", "krbtgt/CORP.LOCAL",
		[]int{etypeRC4HMAC}, good))
	if tag := replyAppTag(reply); tag != krbASRep {
		t.Fatalf("the correct password did not produce an AS-REP (tag %d, error %d)",
			tag, krbErrorCode(t, reply))
	}
	e := col.waitFor(t, "the successful authentication", func(e *event.Event) bool {
		return strings.Contains(e.Message, "authenticated with the planted password")
	})
	if e.SeverityID != event.SeverityCritical {
		t.Fatalf("a successful Kerberos logon was recorded at severity %d", e.SeverityID)
	}
}

func TestKerberosOverUDPRefusesToAmplify(t *testing.T) {
	// A KDC that answered a roast in a datagram would be a reflector: the
	// request is small and the AS-REP is not. Real Kerberos already has the
	// answer -- KRB5KRB_ERR_RESPONSE_TOO_BIG -- so the protocol and the
	// containment rule agree.
	_, col, addrs := startFarm(t, ListenerConfig{
		Service: "kerberos", Persona: "windows/dc", DecoyID: "dcy-dc01",
		Protocol: "udp"})

	conn, err := net.Dial("udp", addrs["kerberos"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := asReq("svc_legacy", "CORP.LOCAL", "krbtgt/CORP.LOCAL", []int{etypeRC4HMAC}, nil)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("the KDC said nothing over UDP: %v", err)
	}
	if n >= len(req) {
		t.Fatalf("the UDP reply (%d bytes) is not smaller than the request (%d): "+
			"this decoy could be used as an amplifier", n, len(req))
	}
	if got := krbErrorCode(t, buf[:n]); got != kdcErrResponseTooBig {
		t.Fatalf("UDP reply carried error %d, want KRB5KRB_ERR_RESPONSE_TOO_BIG (%d)",
			got, kdcErrResponseTooBig)
	}
	_ = col
}

func TestKerberosRefusesANonWindowsPersona(t *testing.T) {
	// A Linux web server answering as a domain controller is the sort of
	// inconsistency an attacker notices before anything else.
	p, err := BuildPersona("linux/web", "test-seed-fixed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newKerberos(p, nil); err == nil {
		t.Fatal("a linux persona was allowed to serve a KDC")
	}
}

func TestKerberosBaitAgreesWithWhatLDAPAdvertises(t *testing.T) {
	// An attacker who enumerates svc_sql over LDAP and then cannot roast it
	// over Kerberos has found the seam. One directory, two views.
	p, err := BuildPersona("windows/dc", "test-seed-fixed")
	if err != nil {
		t.Fatal(err)
	}
	dir := buildHoneyDirectory(p)

	for _, e := range dir.Entries {
		spn := e.Get("servicePrincipalName")
		if spn == "" {
			continue
		}
		acct, ok := dir.AccountBySPN(spn)
		if !ok {
			t.Fatalf("LDAP advertises SPN %q but Kerberos has no account for it", spn)
		}
		if !strings.EqualFold(acct.SAM, e.Get("sAMAccountName")) {
			t.Fatalf("SPN %q maps to %q in Kerberos and %q in LDAP",
				spn, acct.SAM, e.Get("sAMAccountName"))
		}
	}

	// The AS-REP roastable account must be flagged in both places.
	acct, ok := dir.Account("svc_legacy")
	if !ok || !acct.NoPreauth {
		t.Fatal("svc_legacy is advertised as pre-auth disabled in LDAP but not in Kerberos")
	}
}

func TestPlantedPasswordsDifferBetweenDeployments(t *testing.T) {
	// A password that is the same everywhere is a signature that identifies
	// MIRAGE from a single cracked hash.
	a, err := BuildPersona("windows/dc", "seed-one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildPersona("windows/dc", "seed-two")
	if err != nil {
		t.Fatal(err)
	}
	pa, _ := buildHoneyDirectory(a).Account("svc_sql")
	pb, _ := buildHoneyDirectory(b).Account("svc_sql")
	if pa.Password == pb.Password {
		t.Fatalf("two deployments planted the same password (%q)", pa.Password)
	}

	// And the same deployment must plant the same one twice, or an attacker
	// who roasts the account after a restart learns the KDC regenerates.
	again, _ := buildHoneyDirectory(a).Account("svc_sql")
	if again.Password != pa.Password {
		t.Fatal("the planted password changed between two builds of the same persona")
	}
}

func TestRC4RoundTripMatchesTheSpec(t *testing.T) {
	// Pinned so that a refactor cannot quietly change the wire format and turn
	// every planted hash into something no cracker will accept.
	key := ntHash("Summer2019!")
	if got := hex.EncodeToString(key); len(got) != 32 {
		t.Fatalf("an NT hash must be 16 bytes, got %d", len(key))
	}
	blob, err := rc4Encrypt(key, krbUsageASRepPart, make([]byte, 8), []byte("hello kerberos"))
	if err != nil {
		t.Fatal(err)
	}
	plain, ok := rc4Decrypt(key, krbUsageASRepPart, blob)
	if !ok || string(plain) != "hello kerberos" {
		t.Fatalf("round trip failed: ok=%v plain=%q", ok, plain)
	}
	if _, ok := rc4Decrypt(ntHash("wrong"), krbUsageASRepPart, blob); ok {
		t.Fatal("the wrong key was accepted; the checksum is not being verified")
	}
}

// --- helpers that do what the attacker's cracker does ------------------------

// crackASREP takes the recorded hash apart and checks it really opens under the
// password, exactly as hashcat mode 18200 would.
func crackASREP(t *testing.T, hash, password string) bool {
	t.Helper()
	_, rest, ok := strings.Cut(hash, ":")
	if !ok {
		return false
	}
	checksumHex, cipherHex, ok := strings.Cut(rest, "$")
	if !ok {
		return false
	}
	return decryptsUnder(t, password, krbUsageASRepPart, checksumHex, cipherHex)
}

// crackTGS does the same for hashcat mode 13100.
func crackTGS(t *testing.T, hash, password string) bool {
	t.Helper()
	_, rest, ok := strings.Cut(hash, "*$")
	if !ok {
		return false
	}
	checksumHex, cipherHex, ok := strings.Cut(rest, "$")
	if !ok {
		return false
	}
	return decryptsUnder(t, password, krbUsageTicket, checksumHex, cipherHex)
}

func decryptsUnder(t *testing.T, password string, usage int, checksumHex, cipherHex string) bool {
	t.Helper()
	checksum, err := hex.DecodeString(checksumHex)
	if err != nil {
		return false
	}
	cipher, err := hex.DecodeString(cipherHex)
	if err != nil {
		return false
	}
	plain, ok := rc4Decrypt(ntHash(password), usage, append(checksum, cipher...))
	if !ok {
		return false
	}
	// A cracker's optimised path also checks that what came out looks like the
	// DER it expects. If this fails the crack would be rejected as a false
	// positive even with the right password.
	return len(plain) > 2 && plain[0]&0xe0 == 0x60
}

// paTimestamp builds a PA-ENC-TS-ENC, the structure a client encrypts to prove
// it knows the password.
func paTimestamp() []byte {
	return derSequence(derCtx(0, derKerberosTime(time.Now().UTC())))
}
