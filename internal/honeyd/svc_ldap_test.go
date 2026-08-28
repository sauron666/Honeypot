package honeyd

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// ldapClient speaks just enough LDAP to drive the decoy the way ldapsearch,
// adfind or BloodHound would.
type ldapClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	id   int
}

func dialLDAP(t *testing.T, addr string) *ldapClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	return &ldapClient{t: t, conn: conn, r: bufio.NewReader(conn)}
}

func (c *ldapClient) next() int { c.id++; return c.id }

// send writes one message and reads responses until a result-done arrives.
func (c *ldapClient) send(msg []byte, terminator byte) [][]byte {
	c.t.Helper()
	if _, err := c.conn.Write(msg); err != nil {
		c.t.Fatalf("ldap write: %v", err)
	}
	var out [][]byte
	for i := 0; i < 600; i++ {
		raw, err := readBERMessage(c.r, 1<<20)
		if err != nil {
			c.t.Fatalf("ldap read: %v", err)
		}
		out = append(out, raw)
		if opTagOf(c.t, raw) == terminator {
			return out
		}
	}
	c.t.Fatal("too many LDAP responses")
	return nil
}

func opTagOf(t *testing.T, raw []byte) byte {
	t.Helper()
	_, body, _, err := berNext(raw)
	if err != nil {
		t.Fatalf("bad LDAP message: %v", err)
	}
	_, _, rest, err := berNext(body)
	if err != nil {
		t.Fatalf("bad LDAP message id: %v", err)
	}
	tag, _, _, err := berNext(rest)
	if err != nil {
		t.Fatalf("bad LDAP operation: %v", err)
	}
	return tag
}

// resultCode extracts the code from a BindResponse or SearchResultDone.
func resultCode(t *testing.T, raw []byte) int {
	t.Helper()
	_, body, _, _ := berNext(raw)
	_, _, rest, _ := berNext(body)
	_, opBody, _, _ := berNext(rest)
	tag, val, _, err := berNext(opBody)
	if err != nil || tag != 0x0a {
		t.Fatalf("no result code in response")
	}
	return berInt(val)
}

// entryDN pulls the object name out of a SearchResultEntry.
func entryDN(t *testing.T, raw []byte) string {
	t.Helper()
	_, body, _, _ := berNext(raw)
	_, _, rest, _ := berNext(body)
	_, opBody, _, _ := berNext(rest)
	tag, val, _, err := berNext(opBody)
	if err != nil || tag != 0x04 {
		return ""
	}
	return string(val)
}

// entryAttrs decodes the attributes of a SearchResultEntry.
func entryAttrs(t *testing.T, raw []byte) map[string][]string {
	t.Helper()
	_, body, _, _ := berNext(raw)
	_, _, rest, _ := berNext(body)
	_, opBody, _, _ := berNext(rest)
	_, _, afterDN, _ := berNext(opBody)
	_, attrSeq, _, err := berNext(afterDN)
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	r := attrSeq
	for len(r) > 0 {
		_, attr, next, err := berNext(r)
		if err != nil {
			break
		}
		_, nameBytes, valsRest, err := berNext(attr)
		if err != nil {
			break
		}
		_, valSet, _, err := berNext(valsRest)
		if err == nil {
			v := valSet
			for len(v) > 0 {
				_, val, vnext, err := berNext(v)
				if err != nil {
					break
				}
				out[string(nameBytes)] = append(out[string(nameBytes)], string(val))
				v = vnext
			}
		}
		r = next
	}
	return out
}

func simpleBind(c *ldapClient, dn, password string) []byte {
	body := berInteger(3)
	body = append(body, berString(dn)...)
	body = append(body, berSeq(0x80, []byte(password))...)
	return ldapMessage(c.next(), ldapBindRequest, body)
}

// searchMessage builds a SearchRequest with a raw filter encoding.
func searchMessage(c *ldapClient, base string, scope int, filter []byte, attrs []string) []byte {
	body := berString(base)
	body = append(body, berEnum(scope)...)
	body = append(body, berEnum(0)...)              // derefAliases
	body = append(body, berInteger(0)...)           // sizeLimit
	body = append(body, berInteger(30)...)          // timeLimit
	body = append(body, berSeq(0x01, []byte{0})...) // typesOnly = false
	body = append(body, filter...)
	var attrList []byte
	for _, a := range attrs {
		attrList = append(attrList, berString(a)...)
	}
	body = append(body, berSeq(0x30, attrList)...)
	return ldapMessage(c.next(), ldapSearchRequest, body)
}

func filterEquality(attr, value string) []byte {
	return berSeq(0xa3, append(berString(attr), berString(value)...))
}

func filterPresent(attr string) []byte { return berSeq(0x87, []byte(attr)) }

func filterAnd(parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return berSeq(0xa0, body)
}

func filterExtensible(rule, attr, value string) []byte {
	body := berSeq(0x81, []byte(rule))
	body = append(body, berSeq(0x82, []byte(attr))...)
	body = append(body, berSeq(0x83, []byte(value))...)
	return berSeq(0xa9, body)
}

func TestLDAPSimpleBindCapturesCleartextPassword(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])

	resp := c.send(simpleBind(c, "CORP\\g.ivanov", "Autumn2025!"), ldapBindResponse)
	if code := resultCode(t, resp[0]); code != ldapSuccess {
		t.Fatalf("bind result = %d", code)
	}

	e := col.waitFor(t, "ldap bind", func(e *event.Event) bool {
		return e.ClassUID == event.ClassAuthentication && e.Mirage.Service == "ldap"
	})
	// This is the point of an LDAP decoy: simple bind sends the password in
	// the clear, so there is nothing to crack.
	if e.GetString("password") != "Autumn2025!" {
		t.Fatalf("captured password = %q", e.GetString("password"))
	}
	if e.GetString("bind_dn") != "CORP\\g.ivanov" {
		t.Fatalf("bind dn = %q", e.GetString("bind_dn"))
	}
	col.waitFor(t, "credential record", func(e *event.Event) bool {
		return e.ClassUID == event.ClassCredentialOffer && e.GetString("auth_method") == "ldap-simple-bind"
	})
}

func TestLDAPAnonymousBindAndRootDSE(t *testing.T) {
	// Every client reads the root DSE first to learn the naming context; a
	// directory that cannot answer that looks broken immediately.
	_, col, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])

	c.send(simpleBind(c, "", ""), ldapBindResponse)
	resp := c.send(searchMessage(c, "", 0, filterPresent("objectClass"), nil), ldapSearchResDone)

	if len(resp) < 2 {
		t.Fatalf("root DSE search returned %d messages", len(resp))
	}
	attrs := entryAttrs(t, resp[0])
	if len(attrs["defaultNamingContext"]) == 0 {
		t.Fatalf("root DSE has no defaultNamingContext: %v", attrs)
	}
	if !strings.HasPrefix(attrs["defaultNamingContext"][0], "DC=") {
		t.Fatalf("naming context = %q", attrs["defaultNamingContext"][0])
	}
	if len(attrs["supportedSASLMechanisms"]) == 0 {
		t.Error("root DSE should advertise SASL mechanisms")
	}
	col.waitFor(t, "anonymous bind", func(e *event.Event) bool {
		return e.GetString("bind_type") == "anonymous"
	})
}

func TestLDAPKerberoastEnumerationIsRecognised(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])
	c.send(simpleBind(c, "CORP\\user", "pw"), ldapBindResponse)

	// The canonical kerberoast query.
	filter := filterAnd(
		filterEquality("objectClass", "user"),
		filterPresent("servicePrincipalName"),
	)
	base := "DC=corp,DC=local"
	resp := c.send(searchMessage(c, base, 2, filter,
		[]string{"sAMAccountName", "servicePrincipalName", "pwdLastSet"}), ldapSearchResDone)

	e := col.waitFor(t, "kerberoast finding", func(e *event.Event) bool {
		return strings.Contains(e.Message, "kerberoast-enumeration")
	})
	if e.SeverityID < event.SeverityHigh {
		t.Fatalf("kerberoast enumeration severity = %s", e.SeverityID)
	}
	if !hasTechnique(e, "T1558.003") {
		t.Fatalf("not mapped to kerberoasting: %+v", e.Mirage.Attack)
	}
	// The filter is the intent, and it must be recorded verbatim.
	if got := e.GetString("ldap_filter"); !strings.Contains(got, "servicePrincipalName=*") {
		t.Fatalf("filter not recorded: %q", got)
	}

	// The query must actually return the bait, or the attacker learns nothing
	// and moves on.
	var found []string
	for _, raw := range resp {
		if opTagOf(t, raw) == ldapSearchResEntry {
			found = append(found, entryDN(t, raw))
		}
	}
	if len(found) < 3 {
		t.Fatalf("kerberoast query returned %d accounts: %v", len(found), found)
	}
	for _, dn := range found {
		if !strings.Contains(dn, "svc_") {
			t.Errorf("unexpected account in the kerberoast answer: %s", dn)
		}
	}
}

func TestLDAPASREPRoastEnumerationIsRecognised(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])
	c.send(simpleBind(c, "CORP\\user", "pw"), ldapBindResponse)

	// userAccountControl:1.2.840.113556.1.4.803:=4194304 -- accounts with
	// Kerberos pre-authentication disabled.
	filter := filterAnd(
		filterEquality("objectClass", "user"),
		filterExtensible("1.2.840.113556.1.4.803", "userAccountControl", "4194304"),
	)
	resp := c.send(searchMessage(c, "DC=corp,DC=local", 2, filter,
		[]string{"sAMAccountName"}), ldapSearchResDone)

	e := col.waitFor(t, "as-rep roast finding", func(e *event.Event) bool {
		return strings.Contains(e.Message, "asrep-roast-enumeration")
	})
	if !hasTechnique(e, "T1558.004") {
		t.Fatalf("not mapped to AS-REP roasting: %+v", e.Mirage.Attack)
	}

	// The bitwise matching rule has to be evaluated properly, or the bait
	// never comes back and the decoy looks empty.
	var dns []string
	for _, raw := range resp {
		if opTagOf(t, raw) == ldapSearchResEntry {
			dns = append(dns, entryDN(t, raw))
		}
	}
	if len(dns) != 1 || !strings.Contains(dns[0], "svc_legacy") {
		t.Fatalf("the AS-REP roastable account was not returned: %v", dns)
	}
}

func TestLDAPCertificateTemplateHuntIsRecognised(t *testing.T) {
	_, col, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])
	c.send(simpleBind(c, "CORP\\user", "pw"), ldapBindResponse)

	base := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
	resp := c.send(searchMessage(c, base, 2, filterEquality("objectClass", "pKICertificateTemplate"),
		[]string{"cn", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage"}), ldapSearchResDone)

	e := col.waitFor(t, "adcs finding", func(e *event.Event) bool {
		return strings.Contains(e.Message, "adcs-template-enumeration")
	})
	if !hasTechnique(e, "T1649") {
		t.Fatalf("not mapped to certificate theft: %+v", e.Mirage.Attack)
	}

	var attrs map[string][]string
	for _, raw := range resp {
		if opTagOf(t, raw) == ldapSearchResEntry {
			attrs = entryAttrs(t, raw)
		}
	}
	if attrs == nil {
		t.Fatal("no certificate template was returned")
	}
	// Enrollee-supplied subject plus client authentication is the shape that
	// makes a template look exploitable.
	if len(attrs["msPKI-Certificate-Name-Flag"]) == 0 || attrs["msPKI-Certificate-Name-Flag"][0] != "1" {
		t.Errorf("the template does not look ESC1-shaped: %v", attrs)
	}
}

func TestLDAPRequestedAttributesAreHonoured(t *testing.T) {
	// A directory that ignores the requested attribute list and dumps
	// everything is not how a real one behaves.
	_, _, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])
	c.send(simpleBind(c, "CORP\\user", "pw"), ldapBindResponse)

	resp := c.send(searchMessage(c, "DC=corp,DC=local", 2,
		filterEquality("sAMAccountName", "svc_sql"), []string{"sAMAccountName"}), ldapSearchResDone)

	for _, raw := range resp {
		if opTagOf(t, raw) != ldapSearchResEntry {
			continue
		}
		attrs := entryAttrs(t, raw)
		if len(attrs) != 1 {
			t.Fatalf("asked for one attribute, got %d: %v", len(attrs), attrs)
		}
		if len(attrs["sAMAccountName"]) == 0 {
			t.Fatalf("the requested attribute is missing: %v", attrs)
		}
	}
}

func TestLDAPUnknownBaseReturnsNoSuchObject(t *testing.T) {
	_, _, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])
	c.send(simpleBind(c, "", ""), ldapBindResponse)

	resp := c.send(searchMessage(c, "DC=someone,DC=else", 2,
		filterPresent("objectClass"), nil), ldapSearchResDone)
	if code := resultCode(t, resp[len(resp)-1]); code != ldapNoSuchObject {
		t.Fatalf("result = %d, want noSuchObject (%d)", code, ldapNoSuchObject)
	}
}

func TestLDAPSurvivesMalformedInput(t *testing.T) {
	// Directory ports attract every scanner in existence.
	_, _, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})

	for _, payload := range [][]byte{
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00},
		{0x00, 0x00},
		[]byte("GET / HTTP/1.1\r\n\r\n"),
	} {
		conn, err := net.Dial("tcp", addrs["ldap"])
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write(payload)
		buf := make([]byte, 256)
		conn.Read(buf)
		conn.Close()
	}

	c := dialLDAP(t, addrs["ldap"])
	if code := resultCode(t, c.send(simpleBind(c, "", ""), ldapBindResponse)[0]); code != ldapSuccess {
		t.Fatal("the directory stopped working after malformed input")
	}
}

func TestLDAPCollectorHintForLongAttributeLists(t *testing.T) {
	// BloodHound and adfind ask for dozens of attributes at once; a person
	// does not.
	_, col, addrs := startFarm(t, ListenerConfig{Service: "ldap", Persona: "windows/dc"})
	c := dialLDAP(t, addrs["ldap"])
	c.send(simpleBind(c, "CORP\\user", "pw"), ldapBindResponse)

	attrs := []string{
		"samaccountname", "distinguishedname", "objectsid", "objectclass", "primarygroupid",
		"useraccountcontrol", "admincount", "memberof", "member", "serviceprincipalname",
		"msds-allowedtodelegateto", "msds-allowedtoactonbehalfofotheridentity",
		"ntsecuritydescriptor", "lastlogon", "lastlogontimestamp", "pwdlastset",
		"description", "displayname", "mail", "title",
	}
	c.send(searchMessage(c, "DC=corp,DC=local", 2, filterPresent("objectClass"), attrs), ldapSearchResDone)

	e := col.waitFor(t, "collector hint", func(e *event.Event) bool {
		return e.GetString("collector_hint") != ""
	})
	if !strings.Contains(e.GetString("collector_hint"), "BloodHound") {
		t.Fatalf("hint = %q", e.GetString("collector_hint"))
	}
}
