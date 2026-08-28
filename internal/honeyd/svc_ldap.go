package honeyd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("ldap", newLDAP) }

// ldapSvc serves a decoy Active Directory over LDAP.
//
// Every serious intrusion into a Windows estate runs LDAP queries early --
// BloodHound, adfind, ldapsearch and PowerView all speak it -- and the queries
// themselves are the intent, written out in full. A filter asking for accounts
// with a servicePrincipalName is a kerberoast; one asking for accounts with
// pre-authentication disabled is an AS-REP roast; one reading a certificate
// template's enrolment flags is certificate-based privilege escalation. None of
// those has a benign explanation.
//
// A simple bind is better still: LDAP sends the password in the clear.
type ldapSvc struct {
	p   *Persona
	dir *Directory
	// acceptBind decides whether credentials are accepted. Accepting keeps the
	// attacker enumerating, which is where the value is.
	acceptBind bool
}

func newLDAP(p *Persona, opts map[string]any) (Service, error) {
	l := &ldapSvc{p: p, dir: buildHoneyDirectory(p), acceptBind: true}
	if v, ok := opts["accept_bind"].(bool); ok {
		l.acceptBind = v
	}
	return l, nil
}

func (l *ldapSvc) Type() string { return "ldap" }

// LDAP protocol operation tags.
const (
	ldapBindRequest      = 0x60
	ldapBindResponse     = 0x61
	ldapUnbindRequest    = 0x42
	ldapSearchRequest    = 0x63
	ldapSearchResEntry   = 0x64
	ldapSearchResDone    = 0x65
	ldapAbandonRequest   = 0x50
	ldapExtendedRequest  = 0x77
	ldapExtendedResponse = 0x78
)

// LDAP result codes.
const (
	ldapSuccess            = 0
	ldapOperationsError    = 1
	ldapInvalidCredentials = 49
	ldapNoSuchObject       = 32
	ldapProtocolError      = 2
	ldapUnwillingToPerform = 53
)

func (l *ldapSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)
	bound := ""

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))

		raw, err := readBERMessage(r, 8*1024*1024)
		if err != nil {
			return nil
		}
		s.Record("in", raw[:min(len(raw), 256)])

		_, body, _, err := berNext(raw)
		if err != nil {
			s.Note(event.SeverityMedium, "malformed LDAP message: %v", err)
			return nil
		}
		idTag, idBytes, rest, err := berNext(body)
		if err != nil || idTag != 0x02 {
			s.Note(event.SeverityMedium, "LDAP message without a message id")
			return nil
		}
		messageID := berInt(idBytes)

		opTag, opBody, _, err := berNext(rest)
		if err != nil {
			s.Note(event.SeverityMedium, "LDAP message without an operation")
			return nil
		}

		var resp []byte
		switch opTag {
		case ldapBindRequest:
			resp, bound = l.bind(messageID, opBody, s)

		case ldapSearchRequest:
			resp = l.search(messageID, opBody, bound, s)

		case ldapUnbindRequest:
			return nil

		case ldapAbandonRequest:
			continue // no response is defined for abandon

		case ldapExtendedRequest:
			resp = l.extended(messageID, opBody, s)

		default:
			s.Note(event.SeverityLow, "unsupported LDAP operation 0x%02x", opTag)
			resp = ldapMessage(messageID, ldapSearchResDone,
				ldapResult(ldapProtocolError, "", "operation not supported"))
		}

		if len(resp) > 0 {
			s.Record("out", resp[:min(len(resp), 128)])
			if _, err := conn.Write(resp); err != nil {
				return err
			}
		}
	}
}

// bind handles authentication, which on LDAP means a password in the clear.
func (l *ldapSvc) bind(messageID int, body []byte, s *Session) ([]byte, string) {
	verTag, verBytes, rest, err := berNext(body)
	if err != nil || verTag != 0x02 {
		return ldapMessage(messageID, ldapBindResponse,
			ldapResult(ldapProtocolError, "", "malformed bind")), ""
	}
	version := berInt(verBytes)

	nameTag, nameBytes, rest2, err := berNext(rest)
	if err != nil || nameTag != 0x04 {
		return ldapMessage(messageID, ldapBindResponse,
			ldapResult(ldapProtocolError, "", "malformed bind")), ""
	}
	name := string(nameBytes)

	authTag, authBody, _, err := berNext(rest2)
	if err != nil {
		return ldapMessage(messageID, ldapBindResponse,
			ldapResult(ldapProtocolError, "", "malformed bind")), ""
	}

	switch authTag {
	case 0x80: // simple
		password := string(authBody)
		if name == "" && password == "" {
			// Anonymous bind. Many directories allow it, and a scanner will
			// try it first.
			e := s.Event(event.ClassAuthentication, 1, event.SeverityLow).
				WithMessage("anonymous LDAP bind (version %d)", version)
			e.Set("bind_type", "anonymous").Set("ldap_version", version)
			s.Emit(e)
			return ldapMessage(messageID, ldapBindResponse, ldapResult(ldapSuccess, "", "")), ""
		}

		accepted := l.acceptBind
		s.AddCredential(Credential{
			Username: name, Secret: password, Method: "ldap-simple-bind", Accepted: accepted,
		})
		e := s.Event(event.ClassAuthentication, 1, event.SeverityHigh).
			WithMessage("LDAP simple bind for %q", name).
			WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1110", Name: "Brute Force"})
		e.Actor = &event.Actor{User: name, Session: s.ID}
		e.Set("bind_dn", name).
			Set("password", password).
			Set("ldap_version", version).
			Set("accepted", accepted).
			// This is the point worth making in the alert itself.
			Set("note", "LDAP simple bind sends the password in cleartext")
		s.Emit(e)

		if !accepted {
			time.Sleep(700 * time.Millisecond)
			return ldapMessage(messageID, ldapBindResponse,
				ldapResult(ldapInvalidCredentials, "", "80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e")), ""
		}
		return ldapMessage(messageID, ldapBindResponse, ldapResult(ldapSuccess, "", "")), name

	case 0xa3: // SASL
		mechTag, mechBytes, credRest, err := berNext(authBody)
		mech := ""
		if err == nil && mechTag == 0x04 {
			mech = string(mechBytes)
		}
		var creds []byte
		if _, credBytes, _, err := berNext(credRest); err == nil {
			creds = credBytes
		}

		// GSS-SPNEGO carries NTLM, which means the same NetNTLMv2 capture the
		// SMB decoy performs is available here.
		if ntlm := findNTLMSSP(creds); ntlm != nil && messageType(ntlm) == 3 {
			if auth, err := parseNTLMAuth(ntlm); err == nil {
				e := s.Event(event.ClassAuthentication, 1, event.SeverityHigh).
					WithMessage("LDAP NTLM bind from %s\\%s on workstation %s",
						auth.Domain, auth.User, auth.Workstation).
					WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1110", Name: "Brute Force"})
				e.Set("username", auth.User).Set("domain", auth.Domain).
					Set("workstation", auth.Workstation).Set("sasl_mechanism", mech)
				s.Emit(e)
				s.AddCredential(Credential{
					Username: auth.User, Method: "ldap-sasl-ntlm", Accepted: l.acceptBind,
				})
			}
		} else {
			e := s.Event(event.ClassAuthentication, 1, event.SeverityMedium).
				WithMessage("LDAP SASL bind using %s", mech)
			e.Set("sasl_mechanism", mech).Set("bind_dn", name)
			s.Emit(e)
		}
		// Answering "in progress" once keeps a real client's exchange moving.
		return ldapMessage(messageID, ldapBindResponse, ldapResult(ldapSuccess, "", "")), name

	default:
		return ldapMessage(messageID, ldapBindResponse,
			ldapResult(ldapUnwillingToPerform, "", "unsupported authentication method")), ""
	}
}

// search answers a query and, more importantly, records what was asked.
func (l *ldapSvc) search(messageID int, body []byte, bound string, s *Session) []byte {
	baseTag, baseBytes, rest, err := berNext(body)
	if err != nil || baseTag != 0x04 {
		return ldapMessage(messageID, ldapSearchResDone,
			ldapResult(ldapProtocolError, "", "malformed search"))
	}
	base := string(baseBytes)

	scopeTag, scopeBytes, rest, err := berNext(rest)
	if err != nil || scopeTag != 0x0a {
		return ldapMessage(messageID, ldapSearchResDone,
			ldapResult(ldapProtocolError, "", "malformed search"))
	}
	scope := berInt(scopeBytes)

	// Skip derefAliases, sizeLimit, timeLimit and typesOnly.
	for i := 0; i < 4; i++ {
		if _, _, rest, err = berNext(rest); err != nil {
			return ldapMessage(messageID, ldapSearchResDone,
				ldapResult(ldapProtocolError, "", "malformed search"))
		}
	}

	filterTag, filterBody, rest, err := berNext(rest)
	if err != nil {
		return ldapMessage(messageID, ldapSearchResDone,
			ldapResult(ldapProtocolError, "", "malformed filter"))
	}
	filter := filterString(filterTag, filterBody)
	attrs := parseAttributeList(rest)

	l.recordSearch(base, scope, filter, attrs, s)

	// The root DSE: what every client reads first to learn the naming context.
	if base == "" && scope == 0 {
		return append(
			ldapMessage(messageID, ldapSearchResEntry, l.rootDSE()),
			ldapMessage(messageID, ldapSearchResDone, ldapResult(ldapSuccess, "", ""))...)
	}

	if !strings.EqualFold(strings.TrimSpace(base), l.dir.BaseDN) &&
		!strings.HasSuffix(strings.ToLower(base), strings.ToLower(l.dir.BaseDN)) {
		return ldapMessage(messageID, ldapSearchResDone,
			ldapResult(ldapNoSuchObject, "", "0000208D: NameErr: DSID-03100238, problem 2001 (NO_OBJECT)"))
	}

	matches := l.dir.Find(base, scope, func(e *Entry) bool {
		return filterMatch(filterTag, filterBody, e)
	})

	var out []byte
	const maxEntries = 500
	for i, e := range matches {
		if i >= maxEntries {
			break
		}
		out = append(out, ldapMessage(messageID, ldapSearchResEntry, encodeEntry(e, attrs))...)
	}
	return append(out, ldapMessage(messageID, ldapSearchResDone, ldapResult(ldapSuccess, "", ""))...)
}

// searchIntent maps a query to the attack it belongs to. The filter is the
// intent: there is no other reason to write these.
var searchIntent = []struct {
	needles   []string
	finding   string
	technique event.Technique
	severity  event.Severity
}{
	{[]string{"serviceprincipalname="}, "kerberoast-enumeration",
		event.Technique{Tactic: "TA0006", Technique: "T1558.003", Name: "Kerberoasting"}, event.SeverityHigh},
	{[]string{"4194304", "dont_req_preauth"}, "asrep-roast-enumeration",
		event.Technique{Tactic: "TA0006", Technique: "T1558.004", Name: "AS-REP Roasting"}, event.SeverityHigh},
	{[]string{"ms-mcs-admpwd"}, "laps-password-hunt",
		event.Technique{Tactic: "TA0006", Technique: "T1555", Name: "Credentials from Password Stores"}, event.SeverityHigh},
	{[]string{"pkicertificatetemplate", "mspki-certificate-name-flag", "certificate templates"},
		"adcs-template-enumeration",
		event.Technique{Tactic: "TA0004", Technique: "T1649", Name: "Steal or Forge Authentication Certificates"}, event.SeverityHigh},
	{[]string{"msds-managedpassword", "gmsa"}, "gmsa-password-hunt",
		event.Technique{Tactic: "TA0006", Technique: "T1555", Name: "Credentials from Password Stores"}, event.SeverityHigh},
	{[]string{"msds-allowedtoactonbehalfofotheridentity", "msds-allowedtodelegateto", "trustedtoauthfordelegation"},
		"delegation-abuse-hunt",
		event.Technique{Tactic: "TA0004", Technique: "T1134.001", Name: "Token Impersonation"}, event.SeverityHigh},
	{[]string{"admincount=1"}, "privileged-account-enumeration",
		event.Technique{Tactic: "TA0007", Technique: "T1069.002", Name: "Domain Groups"}, event.SeverityMedium},
	{[]string{"objectcategory=computer", "objectclass=computer"}, "computer-enumeration",
		event.Technique{Tactic: "TA0007", Technique: "T1018", Name: "Remote System Discovery"}, event.SeverityMedium},
	{[]string{"objectclass=trusteddomain"}, "trust-enumeration",
		event.Technique{Tactic: "TA0007", Technique: "T1482", Name: "Domain Trust Discovery"}, event.SeverityMedium},
	{[]string{"objectclass=user", "objectcategory=person", "samaccounttype"}, "user-enumeration",
		event.Technique{Tactic: "TA0007", Technique: "T1087.002", Name: "Domain Account Discovery"}, event.SeverityMedium},
	{[]string{"objectclass=group"}, "group-enumeration",
		event.Technique{Tactic: "TA0007", Technique: "T1069.002", Name: "Domain Groups"}, event.SeverityMedium},
}

func (l *ldapSvc) recordSearch(base string, scope int, filter string, attrs []string, s *Session) {
	haystack := strings.ToLower(filter + " " + base + " " + strings.Join(attrs, " "))

	sev := event.SeverityLow
	var findings []string
	var techniques []event.Technique
	for _, intent := range searchIntent {
		for _, n := range intent.needles {
			if strings.Contains(haystack, n) {
				findings = append(findings, intent.finding)
				techniques = append(techniques, intent.technique)
				if intent.severity > sev {
					sev = intent.severity
				}
				break
			}
		}
	}

	class := event.ClassDecoyInteraction
	msg := fmt.Sprintf("LDAP search %s scope=%s filter=%s", orEmpty(base, "<rootDSE>"), scopeName(scope), filter)
	if len(findings) > 0 {
		class = event.ClassDetectionFinding
		msg = fmt.Sprintf("LDAP %s: filter=%s", strings.Join(findings, ", "), filter)
	}

	e := s.Event(class, 1, sev).WithMessage("%s", msg).WithAttack(techniques...)
	e.Set("ldap_base", base).
		Set("ldap_scope", scopeName(scope)).
		Set("ldap_filter", filter).
		Set("ldap_attributes", attrs)
	if len(findings) > 0 {
		e.Set("findings", findings)
	}
	// A query that names many attributes at once is a collection tool rather
	// than a person, and saying which is useful in a report.
	if len(attrs) > 15 {
		e.Set("collector_hint", "the attribute list is long enough to look like an automated collector (BloodHound, adfind)")
	}
	s.Emit(e)
}

func (l *ldapSvc) extended(messageID int, body []byte, s *Session) []byte {
	oid := ""
	if tag, val, _, err := berNext(body); err == nil && tag == 0x80 {
		oid = string(val)
	}
	s.Note(event.SeverityLow, "LDAP extended request %s", orEmpty(oid, "<unknown>"))
	// StartTLS is the usual request; refusing it is ordinary for a directory
	// that has no certificate, and avoids a half-working TLS layer that would
	// be far more detectable than a refusal.
	return ldapMessage(messageID, ldapExtendedResponse,
		ldapResult(ldapUnwillingToPerform, "", "TLS not supported on this port"))
}

func (l *ldapSvc) rootDSE() []byte {
	e := &Entry{DN: "", Attributes: map[string][]string{
		"objectClass":                   {"top", "DMD"},
		"defaultNamingContext":          {l.dir.BaseDN},
		"rootDomainNamingContext":       {l.dir.BaseDN},
		"configurationNamingContext":    {"CN=Configuration," + l.dir.BaseDN},
		"schemaNamingContext":           {"CN=Schema,CN=Configuration," + l.dir.BaseDN},
		"namingContexts":                {l.dir.BaseDN, "CN=Configuration," + l.dir.BaseDN},
		"dnsHostName":                   {strings.ToLower(l.dir.DCHostname) + "." + l.dir.Domain},
		"serverName":                    {"CN=" + l.dir.DCHostname + ",CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration," + l.dir.BaseDN},
		"ldapServiceName":               {l.dir.Domain + ":" + strings.ToLower(l.dir.DCHostname) + "$@" + strings.ToUpper(l.dir.Domain)},
		"domainFunctionality":           {"7"},
		"forestFunctionality":           {"7"},
		"domainControllerFunctionality": {"7"},
		"supportedLDAPVersion":          {"3", "2"},
		"supportedSASLMechanisms":       {"GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"},
		"currentTime":                   {generalizedTime(time.Now())},
		"isSynchronized":                {"TRUE"},
	}}
	return encodeEntry(e, nil)
}

// --- filter handling --------------------------------------------------------

// filterString renders a filter in RFC 4515 form. This is the single most
// valuable field the decoy records: it is the attacker's intent, written out.
func filterString(tag byte, body []byte) string {
	switch tag {
	case 0xa0, 0xa1: // and, or
		op := "&"
		if tag == 0xa1 {
			op = "|"
		}
		var parts []string
		rest := body
		for len(rest) > 0 {
			t, v, next, err := berNext(rest)
			if err != nil {
				break
			}
			parts = append(parts, filterString(t, v))
			rest = next
		}
		return "(" + op + strings.Join(parts, "") + ")"

	case 0xa2: // not
		t, v, _, err := berNext(body)
		if err != nil {
			return "(!)"
		}
		return "(!" + filterString(t, v) + ")"

	case 0xa3, 0xa5, 0xa6, 0xa8: // equality, >=, <=, approx
		op := map[byte]string{0xa3: "=", 0xa5: ">=", 0xa6: "<=", 0xa8: "~="}[tag]
		attr, value, err := twoStrings(body)
		if err != nil {
			return "(?)"
		}
		return "(" + attr + op + escapeFilterValue(value) + ")"

	case 0xa4: // substrings
		attrTag, attrBytes, rest, err := berNext(body)
		if err != nil || attrTag != 0x04 {
			return "(?=*)"
		}
		_, seq, _, err := berNext(rest)
		if err != nil {
			return "(" + string(attrBytes) + "=*)"
		}
		var initial, final string
		var anys []string
		r := seq
		for len(r) > 0 {
			t, v, next, err := berNext(r)
			if err != nil {
				break
			}
			switch t {
			case 0x80:
				initial = string(v)
			case 0x81:
				anys = append(anys, string(v))
			case 0x82:
				final = string(v)
			}
			r = next
		}
		return "(" + string(attrBytes) + "=" + initial + "*" +
			strings.Join(anys, "*") + map[bool]string{true: "", false: "*"}[len(anys) == 0] + final + ")"

	case 0x87: // present
		return "(" + string(body) + "=*)"

	case 0xa9: // extensibleMatch
		var rule, attr, value string
		r := body
		for len(r) > 0 {
			t, v, next, err := berNext(r)
			if err != nil {
				break
			}
			switch t {
			case 0x81:
				rule = string(v)
			case 0x82:
				attr = string(v)
			case 0x83:
				value = string(v)
			}
			r = next
		}
		if rule != "" {
			return "(" + attr + ":" + rule + ":=" + value + ")"
		}
		return "(" + attr + ":=" + value + ")"

	default:
		return fmt.Sprintf("(<filter 0x%02x>)", tag)
	}
}

func escapeFilterValue(s string) string {
	r := strings.NewReplacer("(", `\28`, ")", `\29`, "*", `\2a`, `\`, `\5c`)
	return r.Replace(s)
}

func twoStrings(b []byte) (string, string, error) {
	t1, v1, rest, err := berNext(b)
	if err != nil || t1 != 0x04 {
		return "", "", fmt.Errorf("expected an attribute description")
	}
	t2, v2, _, err := berNext(rest)
	if err != nil || t2 != 0x04 {
		return string(v1), "", nil
	}
	return string(v1), string(v2), nil
}

// filterMatch evaluates a filter against an entry. It is deliberately
// permissive: a decoy that answers plausibly is worth more than one that is
// pedantically correct, and an unsupported construct returning nothing would
// make the directory look broken.
func filterMatch(tag byte, body []byte, e *Entry) bool {
	switch tag {
	case 0xa0: // and
		rest := body
		for len(rest) > 0 {
			t, v, next, err := berNext(rest)
			if err != nil {
				return false
			}
			if !filterMatch(t, v, e) {
				return false
			}
			rest = next
		}
		return true

	case 0xa1: // or
		rest := body
		for len(rest) > 0 {
			t, v, next, err := berNext(rest)
			if err != nil {
				return false
			}
			if filterMatch(t, v, e) {
				return true
			}
			rest = next
		}
		return false

	case 0xa2: // not
		t, v, _, err := berNext(body)
		if err != nil {
			return false
		}
		return !filterMatch(t, v, e)

	case 0xa3: // equality
		attr, value, err := twoStrings(body)
		if err != nil {
			return false
		}
		for k, vals := range e.Attributes {
			if !strings.EqualFold(k, attr) {
				continue
			}
			for _, v := range vals {
				if strings.EqualFold(v, value) {
					return true
				}
			}
		}
		return false

	case 0x87: // present
		return e.Has(string(body))

	case 0xa4: // substrings: match on the initial part, which is enough here
		attrTag, attrBytes, rest, err := berNext(body)
		if err != nil || attrTag != 0x04 {
			return false
		}
		_, seq, _, err := berNext(rest)
		if err != nil {
			return e.Has(string(attrBytes))
		}
		value := strings.ToLower(e.Get(string(attrBytes)))
		if value == "" {
			return false
		}
		r := seq
		for len(r) > 0 {
			t, v, next, err := berNext(r)
			if err != nil {
				break
			}
			if !strings.Contains(value, strings.ToLower(string(v))) {
				return false
			}
			_ = t
			r = next
		}
		return true

	case 0xa9: // extensibleMatch, including the bitwise rules
		var rule, attr, value string
		r := body
		for len(r) > 0 {
			t, v, next, err := berNext(r)
			if err != nil {
				break
			}
			switch t {
			case 0x81:
				rule = string(v)
			case 0x82:
				attr = string(v)
			case 0x83:
				value = string(v)
			}
			r = next
		}
		have, err1 := strconv.ParseInt(e.Get(attr), 10, 64)
		want, err2 := strconv.ParseInt(value, 10, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch rule {
		case "1.2.840.113556.1.4.803": // LDAP_MATCHING_RULE_BIT_AND
			return have&want == want
		case "1.2.840.113556.1.4.804": // LDAP_MATCHING_RULE_BIT_OR
			return have&want != 0
		default:
			return have == want
		}

	default:
		// Unknown constructs match everything rather than nothing: an empty
		// answer to a query a real directory would satisfy is a tell.
		return true
	}
}

func parseAttributeList(rest []byte) []string {
	_, seq, _, err := berNext(rest)
	if err != nil {
		return nil
	}
	var out []string
	r := seq
	for len(r) > 0 {
		t, v, next, err := berNext(r)
		if err != nil {
			break
		}
		if t == 0x04 {
			out = append(out, string(v))
		}
		r = next
	}
	return out
}

// --- encoding ---------------------------------------------------------------

func ldapMessage(messageID int, opTag byte, opBody []byte) []byte {
	body := append(berInteger(messageID), berSeq(opTag, opBody)...)
	return berSeq(0x30, body)
}

func ldapResult(code int, matchedDN, message string) []byte {
	out := berEnum(code)
	out = append(out, berString(matchedDN)...)
	return append(out, berString(message)...)
}

// encodeEntry renders a SearchResultEntry, honouring a requested attribute list.
func encodeEntry(e *Entry, requested []string) []byte {
	wanted := func(name string) bool {
		if len(requested) == 0 {
			return true
		}
		for _, r := range requested {
			if r == "*" || strings.EqualFold(r, name) {
				return true
			}
		}
		return false
	}

	names := make([]string, 0, len(e.Attributes))
	for k := range e.Attributes {
		if wanted(k) {
			names = append(names, k)
		}
	}
	sortStrings(names)

	var attrs []byte
	for _, name := range names {
		var values []byte
		for _, v := range e.Attributes[name] {
			values = append(values, berString(v)...)
		}
		attr := append(berString(name), berSeq(0x31, values)...)
		attrs = append(attrs, berSeq(0x30, attr)...)
	}
	return append(berString(e.DN), berSeq(0x30, attrs)...)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && strings.ToLower(s[j]) < strings.ToLower(s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func scopeName(scope int) string {
	switch scope {
	case 0:
		return "base"
	case 1:
		return "one"
	case 2:
		return "sub"
	default:
		return fmt.Sprint(scope)
	}
}

func orEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
