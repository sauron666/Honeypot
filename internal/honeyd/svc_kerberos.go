package honeyd

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("kerberos", newKerberos) }

// kerberosSvc is a decoy Key Distribution Center.
//
// Until now MIRAGE caught AS-REP roasting and kerberoasting at the moment an
// attacker *enumerated* the accounts over LDAP. That is early, but it is one
// step short: the enumeration says what they are looking for, the ticket
// request says they went and took it. Plenty of tooling skips LDAP entirely --
// Rubeus with a username list, kerbrute, GetNPUsers with -usersfile -- and
// those runs were invisible.
//
// This answers the requests themselves. Three things fall out of that, and none
// of them are available to a platform that only watches LDAP:
//
//   - Username enumeration becomes visible as what it is. A KDC answers an
//     unknown principal differently from a known one, and every tool exploits
//     that. Each name tried is recorded, in order, which is the attacker's
//     wordlist, which is often more identifying than their IP.
//   - A password spray is recognised as a spray. Pre-authentication carries an
//     encrypted timestamp; this KDC actually decrypts it, so a wrong password
//     is distinguishable from a malformed request, and the same password
//     across twenty accounts is distinguishable from twenty passwords against
//     one.
//   - The roast yields something real. The blob handed over is genuine
//     RC4-HMAC over a genuine DER structure, keyed on a planted password, so
//     the attacker's crack succeeds -- and the credential they walk away with
//     is one MIRAGE is watching for everywhere else.
type kerberosSvc struct {
	p   *Persona
	dir *Directory
	// realm is the uppercase Kerberos realm, which is the domain in Windows.
	realm string
	// maxUDP is the largest reply this KDC will put in a datagram. Beyond it,
	// the answer is KRB5KRB_ERR_RESPONSE_TOO_BIG, which is both what a real KDC
	// does and what keeps a decoy from being an amplifier.
	maxUDP int
}

func newKerberos(p *Persona, opts map[string]any) (Service, error) {
	if !isWindowsPersona(p.Name) {
		// A Linux persona serving a domain controller's KDC is the sort of
		// inconsistency an attacker notices before anything else.
		return nil, fmt.Errorf("kerberos: persona %q is not a domain controller; "+
			"use a windows/ persona for this service", p.Name)
	}
	k := &kerberosSvc{
		p: p, dir: buildHoneyDirectory(p),
		realm:  strings.ToUpper(p.Domain),
		maxUDP: 1400,
	}
	if v, ok := opts["realm"].(string); ok && v != "" {
		k.realm = strings.ToUpper(v)
	}
	return k, nil
}

func (k *kerberosSvc) Type() string { return "kerberos" }

// Serve handles Kerberos over TCP, which is where every interesting exchange
// ends up: the replies that matter are too big for a datagram.
func (k *kerberosSvc) Serve(ctx context.Context, conn net.Conn, sess *Session) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil
		}
		size := binary.BigEndian.Uint32(lenBuf[:])
		// The high bit is reserved; a real KDC rejects it, and refusing here
		// keeps a malformed length from becoming a large allocation.
		if size == 0 || size&0x80000000 != 0 || size > 64*1024 {
			sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityLow).
				WithMessage("kerberos: implausible message length %d", size))
			return nil
		}
		msg := make([]byte, size)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return nil
		}
		sess.Record("in", msg)

		reply := k.handle(sess, msg, false)
		if len(reply) == 0 {
			return nil
		}
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], uint32(len(reply)))
		conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := conn.Write(append(out[:], reply...)); err != nil {
			return nil
		}
		sess.Record("out", reply)
	}
}

// ServePacket handles Kerberos over UDP.
//
// Anything substantial is answered with KRB5KRB_ERR_RESPONSE_TOO_BIG rather
// than with the reply itself. That is not a compromise: it is what a real KDC
// does when a reply will not fit, every Kerberos client knows to retry over
// TCP, and it happens to make this service useless as a reflector -- the
// datagram that comes back is smaller than the one that went out. The
// containment rule in docs/04 and the protocol agree for once.
func (k *kerberosSvc) ServePacket(_ context.Context, sess *Session, payload []byte) ([]byte, error) {
	return k.handle(sess, payload, true), nil
}

// handle parses one KDC request and produces one reply.
func (k *kerberosSvc) handle(sess *Session, msg []byte, udp bool) []byte {
	req, err := parseKrbRequest(msg)
	if err != nil {
		sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityLow).
			WithMessage("kerberos: unparseable request (%d bytes)", len(msg)).
			Set("parse_error", err.Error()))
		return k.krbError(kdcErrPolicy, "", "unparseable request")
	}

	switch req.MsgType {
	case krbASReq:
		return k.handleAS(sess, req, udp)
	case krbTGSReq:
		return k.handleTGS(sess, req, udp)
	default:
		sess.Note(event.SeverityLow, "kerberos: message type %d is not a KDC request", req.MsgType)
		return k.krbError(kdcErrPolicy, "", "unsupported message type")
	}
}

// handleAS answers an AS-REQ: the first step of every Kerberos logon, and the
// step both enumeration and AS-REP roasting abuse.
func (k *kerberosSvc) handleAS(sess *Session, req *krbRequest, udp bool) []byte {
	client := principalUser(req.Client)
	if client == "" {
		return k.krbError(kdcErrPrincipalUnknown, "", "no client name")
	}

	acct, known := k.dir.Account(client)
	if !known {
		// This is the enumeration answer, and it has to be the real one: a KDC
		// that returned PREAUTH_REQUIRED for every name would tell kerbrute
		// that every name exists, which no real domain does. Recording the
		// miss is the point -- the list of names tried is the attacker's
		// wordlist, and it identifies their tooling better than a user agent.
		sess.Emit(sess.Event(event.ClassAuthentication, 1, event.SeverityMedium).
			WithMessage("kerberos: user enumeration, %q does not exist in %s", client, k.realm).
			WithAttack(
				event.Technique{Tactic: "TA0007", Technique: "T1087.002", Name: "Account Discovery: Domain Account"},
			).
			Set("principal", client).
			Set("realm", k.realm).
			Set("kdc_error", "KDC_ERR_C_PRINCIPAL_UNKNOWN"))
		return k.krbError(kdcErrPrincipalUnknown, client, "client not found in Kerberos database")
	}

	// No pre-authentication data: either a probe establishing that the account
	// exists, or an AS-REP roast against an account that does not require it.
	if len(req.PAEncTimestamp) == 0 {
		if acct.NoPreauth {
			return k.asrepRoast(sess, req, acct, udp)
		}
		sess.Emit(sess.Event(event.ClassAuthentication, 1, event.SeverityMedium).
			WithMessage("kerberos: %q exists and requires pre-authentication", client).
			WithAttack(
				event.Technique{Tactic: "TA0007", Technique: "T1087.002", Name: "Account Discovery: Domain Account"},
			).
			Set("principal", client).
			Set("realm", k.realm).
			Set("kdc_error", "KDC_ERR_PREAUTH_REQUIRED").
			Set("account_found", true))
		return k.preauthRequired(client)
	}

	// A timestamp was sent, so this is an authentication attempt with a real
	// password guess behind it. Decrypting it is what turns "somebody spoke
	// Kerberos" into "somebody tried Summer2019! against six accounts".
	return k.checkPreauth(sess, req, acct, udp)
}

// asrepRoast hands over the crackable blob, and records exactly what was taken.
func (k *kerberosSvc) asrepRoast(sess *Session, req *krbRequest, acct *KerbAccount, udp bool) []byte {
	if udp {
		return k.tooBig(acct.SAM)
	}
	key := ntHash(acct.Password)
	sessionKey := k.deriveSessionKey(acct.SAM)

	encPart, err := k.encASRepPart(acct, sessionKey)
	if err != nil {
		return k.krbError(kdcErrPolicy, acct.SAM, "internal")
	}
	blob, err := rc4Encrypt(key, krbUsageASRepPart, k.confounder(acct.SAM, "asrep"), encPart)
	if err != nil {
		return k.krbError(kdcErrPolicy, acct.SAM, "internal")
	}

	// The ticket itself is encrypted under krbtgt, which the attacker cannot
	// crack and does not want; only the enc-part above is the prize.
	ticket := k.ticket(acct.SAM, "krbtgt/"+k.realm, k.krbtgtKey(), sessionKey)

	sess.AddCredential(Credential{
		Username: acct.SAM, Secret: "", Method: "kerberos-asrep-roast", Accepted: false,
	})
	sess.Emit(sess.Event(event.ClassCredentialOffer, 1, event.SeverityHigh).
		WithMessage("kerberos: AS-REP roast of %q -- pre-authentication is disabled, "+
			"so a crackable hash was handed over without any password", acct.SAM).
		WithAttack(
			event.Technique{Tactic: "TA0006", Technique: "T1558.004", Name: "Steal or Forge Kerberos Tickets: AS-REP Roasting"},
		).
		Set("principal", acct.SAM).
		Set("realm", k.realm).
		Set("etype", etypeRC4HMAC).
		Set("hashcat_mode", 18200).
		// The hash is recorded so that an analyst can answer the only question
		// that matters afterwards: which credential did they walk away with,
		// and therefore what will they try next.
		Set("asrep_hash", asrepHash(acct.SAM, k.realm, blob)).
		Set("planted_password", acct.Password))

	body := derCtx(0, berInteger(5)) // pvno
	body = append(body, derCtx(1, berInteger(krbASRep))...)
	body = append(body, derCtx(3, derGeneralString(k.realm))...)
	body = append(body, derCtx(4, derPrincipalName(ntPrincipal, acct.SAM))...)
	body = append(body, derCtx(5, ticket)...)
	body = append(body, derCtx(6, derEncryptedData(etypeRC4HMAC, 0, blob))...)
	return derApp(krbASRep, derSequence(body))
}

// checkPreauth verifies an encrypted timestamp against the planted password.
func (k *kerberosSvc) checkPreauth(sess *Session, req *krbRequest, acct *KerbAccount, udp bool) []byte {
	key := ntHash(acct.Password)

	if req.PAEncEtype != etypeRC4HMAC {
		// Only RC4 is implemented. Saying "I do not support that" is what a
		// domain hardened against RC4 downgrade would say in reverse, and it
		// keeps the client talking rather than giving up.
		sess.Emit(sess.Event(event.ClassAuthentication, 1, event.SeverityMedium).
			WithMessage("kerberos: pre-authentication for %q offered etype %d",
				acct.SAM, req.PAEncEtype).
			Set("principal", acct.SAM).
			Set("etype", req.PAEncEtype).
			Set("kdc_error", "KDC_ERR_ETYPE_NOSUPP"))
		return k.krbError(kdcErrEtypeNoSupp, acct.SAM, "encryption type not supported")
	}

	if _, ok := rc4Decrypt(key, krbUsagePAEncTimestamp, req.PAEncTimestamp); !ok {
		// The guess was wrong. This is the single most useful Kerberos event
		// there is: it is unambiguous, it names the account, and a run of them
		// across many accounts is a spray, which no legitimate client produces.
		sess.AddCredential(Credential{
			Username: acct.SAM, Secret: "", Method: "kerberos-preauth", Accepted: false,
		})
		sess.Emit(sess.Event(event.ClassAuthentication, 2, event.SeverityHigh).
			WithMessage("kerberos: pre-authentication failed for %q -- a password was guessed and was wrong",
				acct.SAM).
			WithAttack(
				event.Technique{Tactic: "TA0006", Technique: "T1110.003", Name: "Brute Force: Password Spraying"},
			).
			Set("principal", acct.SAM).
			Set("realm", k.realm).
			Set("kdc_error", "KDC_ERR_PREAUTH_FAILED"))
		return k.krbError(kdcErrPreauthFailed, acct.SAM, "pre-authentication information was invalid")
	}

	// The planted password was guessed. Every other decoy in the deployment is
	// already watching for this value, so the next place it appears is joined
	// to this moment automatically.
	sess.AddCredential(Credential{
		Username: acct.SAM, Secret: acct.Password, Method: "kerberos-preauth", Accepted: true,
	})
	sess.Emit(sess.Event(event.ClassAuthentication, 1, event.SeverityCritical).
		WithMessage("kerberos: %q authenticated with the planted password", acct.SAM).
		WithAttack(
			event.Technique{Tactic: "TA0006", Technique: "T1110.003", Name: "Brute Force: Password Spraying"},
		).
		Set("principal", acct.SAM).
		Set("realm", k.realm).
		Set("authenticated", true))

	if udp {
		return k.tooBig(acct.SAM)
	}
	sessionKey := k.deriveSessionKey(acct.SAM)
	encPart, err := k.encASRepPart(acct, sessionKey)
	if err != nil {
		return k.krbError(kdcErrPolicy, acct.SAM, "internal")
	}
	blob, err := rc4Encrypt(ntHash(acct.Password), krbUsageASRepPart,
		k.confounder(acct.SAM, "asrep"), encPart)
	if err != nil {
		return k.krbError(kdcErrPolicy, acct.SAM, "internal")
	}
	ticket := k.ticket(acct.SAM, "krbtgt/"+k.realm, k.krbtgtKey(), sessionKey)

	body := derCtx(0, berInteger(5))
	body = append(body, derCtx(1, berInteger(krbASRep))...)
	body = append(body, derCtx(3, derGeneralString(k.realm))...)
	body = append(body, derCtx(4, derPrincipalName(ntPrincipal, acct.SAM))...)
	body = append(body, derCtx(5, ticket)...)
	body = append(body, derCtx(6, derEncryptedData(etypeRC4HMAC, 0, blob))...)
	return derApp(krbASRep, derSequence(body))
}

// handleTGS answers a TGS-REQ. Asking for a ticket to a service account with an
// SPN, and asking for it with RC4, is kerberoasting and nothing else.
func (k *kerberosSvc) handleTGS(sess *Session, req *krbRequest, udp bool) []byte {
	spn := req.Service
	if spn == "" {
		return k.krbError(kdcErrSPrincipalUnknown, "", "no service name")
	}

	// A TGT request through the TGS path is renewal, not roasting.
	if strings.HasPrefix(strings.ToLower(spn), "krbtgt/") {
		sess.Note(event.SeverityLow, "kerberos: TGT renewal for %s", spn)
		return k.krbError(kdcErrPolicy, spn, "renewal is not permitted")
	}

	acct, known := k.dir.AccountBySPN(spn)
	if !known {
		sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityMedium).
			WithMessage("kerberos: ticket requested for unknown service %q", spn).
			WithAttack(
				event.Technique{Tactic: "TA0007", Technique: "T1087.002", Name: "Account Discovery: Domain Account"},
			).
			Set("spn", spn).
			Set("kdc_error", "KDC_ERR_S_PRINCIPAL_UNKNOWN"))
		return k.krbError(kdcErrSPrincipalUnknown, spn, "server not found in Kerberos database")
	}
	if udp {
		return k.tooBig(spn)
	}

	// Which etype they asked for is the intent. RC4 first, on a domain whose
	// accounts advertise AES, means they want something hashcat can chew.
	wantedRC4 := len(req.ETypes) == 0 || req.ETypes[0] == etypeRC4HMAC
	sev := event.SeverityHigh
	if wantedRC4 {
		sev = event.SeverityCritical
	}

	sessionKey := k.deriveSessionKey(spn)
	encTicket, err := k.encTicketPart(acct.SAM, sessionKey)
	if err != nil {
		return k.krbError(kdcErrPolicy, spn, "internal")
	}
	blob, err := rc4Encrypt(ntHash(acct.Password), krbUsageTicket,
		k.confounder(spn, "tgs"), encTicket)
	if err != nil {
		return k.krbError(kdcErrPolicy, spn, "internal")
	}

	sess.AddCredential(Credential{
		Username: acct.SAM, Secret: "", Method: "kerberos-kerberoast", Accepted: false,
	})
	sess.Emit(sess.Event(event.ClassCredentialOffer, 1, sev).
		WithMessage("kerberos: kerberoast -- service ticket for %q issued, encrypted with the "+
			"account's own key and crackable offline", spn).
		WithAttack(
			event.Technique{Tactic: "TA0006", Technique: "T1558.003", Name: "Steal or Forge Kerberos Tickets: Kerberoasting"},
		).
		Set("spn", spn).
		Set("principal", acct.SAM).
		Set("realm", k.realm).
		Set("etype", etypeRC4HMAC).
		Set("requested_rc4_first", wantedRC4).
		Set("hashcat_mode", 13100).
		Set("tgs_hash", tgsHash(acct.SAM, k.realm, spn, blob)).
		Set("planted_password", acct.Password))

	ticket := k.ticketWithBlob(spn, blob)
	repEnc, err := rc4Encrypt(k.deriveSessionKey("tgs-rep"), 8,
		k.confounder(spn, "reppart"), encTicket)
	if err != nil {
		return k.krbError(kdcErrPolicy, spn, "internal")
	}

	body := derCtx(0, berInteger(5))
	body = append(body, derCtx(1, berInteger(krbTGSRep))...)
	body = append(body, derCtx(3, derGeneralString(k.realm))...)
	body = append(body, derCtx(4, derPrincipalName(ntPrincipal, principalUser(req.Client)))...)
	body = append(body, derCtx(5, ticket)...)
	body = append(body, derCtx(6, derEncryptedData(etypeRC4HMAC, 0, repEnc))...)
	return derApp(krbTGSRep, derSequence(body))
}

// --- message construction ---------------------------------------------------

// ticket builds a Ticket whose enc-part is encrypted under key.
func (k *kerberosSvc) ticket(client, sname string, key, sessionKey []byte) []byte {
	enc, err := k.encTicketPart(client, sessionKey)
	if err != nil {
		enc = []byte{0x30, 0x00}
	}
	blob, err := rc4Encrypt(key, krbUsageTicket, k.confounder(client+sname, "tkt"), enc)
	if err != nil {
		blob = enc
	}
	return k.ticketWithBlob(sname, blob)
}

func (k *kerberosSvc) ticketWithBlob(sname string, blob []byte) []byte {
	parts := strings.Split(sname, "/")
	nameType := ntPrincipal
	if len(parts) > 1 {
		nameType = ntSrvInst
	}
	body := derCtx(0, berInteger(5))
	body = append(body, derCtx(1, derGeneralString(k.realm))...)
	body = append(body, derCtx(2, derPrincipalName(nameType, parts...))...)
	body = append(body, derCtx(3, derEncryptedData(etypeRC4HMAC, 2, blob))...)
	return derApp(1, derSequence(body))
}

// encASRepPart builds the structure an AS-REP roast decrypts to.
//
// It has to be well-formed DER, not padding: hashcat's optimised kernels
// sanity-check the first bytes of the decryption before accepting a candidate,
// and a blob of noise would be rejected even under the correct password. The
// bait only works if the crack visibly succeeds.
func (k *kerberosSvc) encASRepPart(acct *KerbAccount, sessionKey []byte) ([]byte, error) {
	now := time.Now().UTC()
	body := derCtx(0, k.encryptionKey(sessionKey))
	body = append(body, derCtx(1, derSequence(nil))...) // last-req
	body = append(body, derCtx(2, berInteger(int(now.Unix()&0x7fffffff)))...)
	body = append(body, derCtx(4, derBitString([]byte{0x40, 0xe1, 0x00, 0x00}))...)
	body = append(body, derCtx(5, derKerberosTime(now))...)
	body = append(body, derCtx(6, derKerberosTime(now.Add(10*time.Hour)))...)
	body = append(body, derCtx(7, derKerberosTime(now.Add(7*24*time.Hour)))...)
	body = append(body, derCtx(8, derGeneralString(k.realm))...)
	body = append(body, derCtx(9, derPrincipalName(ntSrvInst, "krbtgt", k.realm))...)
	return derApp(25, derSequence(body)), nil
}

// encTicketPart builds the structure a kerberoast decrypts to.
func (k *kerberosSvc) encTicketPart(client string, sessionKey []byte) ([]byte, error) {
	now := time.Now().UTC()
	body := derCtx(0, derBitString([]byte{0x40, 0xa1, 0x00, 0x00}))
	body = append(body, derCtx(1, k.encryptionKey(sessionKey))...)
	body = append(body, derCtx(2, derGeneralString(k.realm))...)
	body = append(body, derCtx(3, derPrincipalName(ntPrincipal, client))...)
	body = append(body, derCtx(4, derSequence(nil))...) // transited
	body = append(body, derCtx(5, derKerberosTime(now))...)
	body = append(body, derCtx(7, derKerberosTime(now.Add(10*time.Hour)))...)
	body = append(body, derCtx(8, derKerberosTime(now.Add(7*24*time.Hour)))...)
	return derApp(3, derSequence(body)), nil
}

func (k *kerberosSvc) encryptionKey(key []byte) []byte {
	return derSequence(append(
		derCtx(0, berInteger(etypeRC4HMAC)),
		derCtx(1, derOctetString(key))...))
}

// krbError builds a KRB-ERROR, which is most of what a decoy KDC says.
func (k *kerberosSvc) krbError(code int, principal, text string) []byte {
	now := time.Now().UTC()
	body := derCtx(0, berInteger(5))
	body = append(body, derCtx(1, berInteger(krbErrorMsg))...)
	body = append(body, derCtx(4, derKerberosTime(now))...)
	body = append(body, derCtx(5, berInteger(0))...)
	body = append(body, derCtx(6, berInteger(code))...)
	body = append(body, derCtx(9, derGeneralString(k.realm))...)
	body = append(body, derCtx(10, derPrincipalName(ntSrvInst, "krbtgt", k.realm))...)
	if text != "" {
		body = append(body, derCtx(11, derGeneralString(text))...)
	}
	return derApp(krbErrorMsg, derSequence(body))
}

// preauthRequired is the error that also carries the etype hints, which is what
// tells a client -- and a roasting tool -- what this account will accept.
func (k *kerberosSvc) preauthRequired(principal string) []byte {
	// PA-ETYPE-INFO2 advertising RC4: the profile of a neglected account, and
	// the reason an attacker picks this one out of the domain.
	info := derSequence(derSequence(
		append(derCtx(0, berInteger(etypeRC4HMAC)),
			derCtx(1, derGeneralString(k.realm+principal))...)))
	pa := derSequence(derSequence(
		append(derCtx(1, berInteger(paEtypeInfo2)),
			derCtx(2, derOctetString(info))...)))

	now := time.Now().UTC()
	body := derCtx(0, berInteger(5))
	body = append(body, derCtx(1, berInteger(krbErrorMsg))...)
	body = append(body, derCtx(4, derKerberosTime(now))...)
	body = append(body, derCtx(5, berInteger(0))...)
	body = append(body, derCtx(6, berInteger(kdcErrPreauthRequired))...)
	body = append(body, derCtx(9, derGeneralString(k.realm))...)
	body = append(body, derCtx(10, derPrincipalName(ntSrvInst, "krbtgt", k.realm))...)
	body = append(body, derCtx(12, derOctetString(pa))...)
	return derApp(krbErrorMsg, derSequence(body))
}

// tooBig is the "retry over TCP" answer. See ServePacket.
//
// It carries no e-text. A real KDC's TOO_BIG is terse, and every byte here is a
// byte of amplification: this reply has to come back smaller than the datagram
// that provoked it, or a spoofed source address turns the decoy into a weapon.
func (k *kerberosSvc) tooBig(principal string) []byte {
	return k.krbError(kdcErrResponseTooBig, principal, "")
}

// --- deterministic material -------------------------------------------------

// deriveSessionKey mints a session key. It is deterministic per deployment so
// that a decoy that is restarted, or asked the same question twice, gives the
// same answer: an attacker who roasts svc_sql before and after a restart and
// gets two different session keys has learnt the KDC has no state.
func (k *kerberosSvc) deriveSessionKey(label string) []byte {
	sum := sha256.Sum256([]byte(k.p.Seed + "|krb-session|" + k.realm + "|" + label))
	return sum[:16]
}

// krbtgtKey is the key the TGT is sealed with. The attacker cannot crack it and
// does not want to: it exists so the ticket is not obviously empty.
func (k *kerberosSvc) krbtgtKey() []byte {
	sum := sha256.Sum256([]byte(k.p.Seed + "|krbtgt|" + k.realm))
	return sum[:16]
}

// confounder is the eight random-looking bytes RC4-HMAC prepends. Deterministic
// for the same reason as the session key.
func (k *kerberosSvc) confounder(label, purpose string) []byte {
	sum := sha256.Sum256([]byte(k.p.Seed + "|krb-conf|" + purpose + "|" + label))
	return sum[:8]
}

// principalUser reduces a principal to the account name an operator recognises.
func principalUser(p string) string {
	if p == "" {
		return ""
	}
	if i := strings.IndexByte(p, '@'); i > 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return p
}

var _ PacketService = (*kerberosSvc)(nil)
