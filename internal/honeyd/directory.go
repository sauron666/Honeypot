package honeyd

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Entry is one object in a decoy directory.
type Entry struct {
	DN         string
	Attributes map[string][]string
	// Bait marks an object that exists only to be found. Enumerating it is
	// what a kerberoast, an AS-REP roast or an ADCS template hunt looks like.
	Bait string
}

// Get returns the first value of an attribute.
func (e *Entry) Get(name string) string {
	for k, v := range e.Attributes {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// Has reports whether an attribute is present.
func (e *Entry) Has(name string) bool {
	for k, v := range e.Attributes {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return true
		}
	}
	return false
}

// Directory is a decoy LDAP tree.
//
// It exists to be enumerated. Every serious intrusion into a Windows estate
// runs LDAP queries early -- BloodHound, adfind, ldapsearch, PowerView all
// speak it -- and the queries themselves say exactly what the attacker is
// hunting for. A directory that answers plausibly gets the whole shopping list.
type Directory struct {
	BaseDN     string
	Domain     string
	NetBIOS    string
	DCHostname string
	Entries    []*Entry
}

// Find returns entries at or below base whose attributes satisfy match.
func (d *Directory) Find(base string, scope int, match func(*Entry) bool) []*Entry {
	base = strings.ToLower(strings.TrimSpace(base))
	var out []*Entry
	for _, e := range d.Entries {
		dn := strings.ToLower(e.DN)
		switch scope {
		case 0: // base object
			if dn != base {
				continue
			}
		case 1: // one level
			if !strings.HasSuffix(dn, base) || dn == base {
				continue
			}
			rest := strings.TrimSuffix(dn, base)
			if strings.Count(rest, ",") != 1 {
				continue
			}
		default: // subtree
			if base != "" && !strings.HasSuffix(dn, base) {
				continue
			}
		}
		if match == nil || match(e) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out
}

// windowsFileTime renders a time the way Active Directory stores it.
func windowsFileTime(t time.Time) string {
	return fmt.Sprintf("%d", (t.Unix()+11644473600)*10000000)
}

// generalizedTime renders a time in LDAP's own format.
func generalizedTime(t time.Time) string {
	return t.UTC().Format("20060102150405") + ".0Z"
}

// buildHoneyDirectory constructs an Active Directory that looks like a real
// small company's, with a handful of deliberately baited objects.
//
// The bait is chosen so that finding it is unambiguous. No legitimate process
// enumerates service accounts by their SPN, hunts for accounts without
// pre-authentication, or reads a certificate template's enrolment flags. Each
// of those is a specific, named attack technique and nothing else.
func buildHoneyDirectory(p *Persona) *Directory {
	domain := p.Domain
	if domain == "" {
		domain = "corp.local"
	}
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, part := range parts {
		dcParts = append(dcParts, "DC="+part)
	}
	base := strings.Join(dcParts, ",")
	netbios := strings.ToUpper(parts[0])

	d := &Directory{
		BaseDN: base, Domain: domain, NetBIOS: netbios,
		DCHostname: strings.ToUpper(p.Hostname),
	}
	add := func(dn string, bait string, attrs map[string][]string) {
		d.Entries = append(d.Entries, &Entry{DN: dn, Attributes: attrs, Bait: bait})
	}

	add(base, "", map[string][]string{
		"objectClass":               {"top", "domain", "domainDNS"},
		"distinguishedName":         {base},
		"name":                      {parts[0]},
		"dc":                        {parts[0]},
		"objectCategory":            {"CN=Domain-DNS,CN=Schema,CN=Configuration," + base},
		"ms-DS-MachineAccountQuota": {"10"},
		"maxPwdAge":                 {"-36288000000000"},
		"lockoutThreshold":          {"0"},
		"whenCreated":               {generalizedTime(time.Now().Add(-6 * 365 * 24 * time.Hour))},
	})

	for _, ou := range []string{"Users", "Computers", "Servers", "Service Accounts", "IT", "Finance"} {
		add("OU="+ou+","+base, "", map[string][]string{
			"objectClass":       {"top", "organizationalUnit"},
			"ou":                {ou},
			"distinguishedName": {"OU=" + ou + "," + base},
		})
	}

	// --- ordinary users, so the baited ones do not stand out ----------------
	people := []struct{ cn, sam, title, dept string }{
		{"Maria Petrova", "m.petrova", "Financial Controller", "Finance"},
		{"Georgi Ivanov", "g.ivanov", "Systems Engineer", "IT"},
		{"Elena Dimitrova", "e.dimitrova", "HR Manager", "HR"},
		{"Nikolay Stoyanov", "n.stoyanov", "Sales Director", "Sales"},
		{"Ivan Kolev", "i.kolev", "Service Desk", "IT"},
	}
	for _, u := range people {
		dn := fmt.Sprintf("CN=%s,OU=Users,%s", u.cn, base)
		add(dn, "", map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user"},
			"objectCategory":     {"CN=Person,CN=Schema,CN=Configuration," + base},
			"cn":                 {u.cn},
			"name":               {u.cn},
			"sAMAccountName":     {u.sam},
			"userPrincipalName":  {u.sam + "@" + domain},
			"displayName":        {u.cn},
			"title":              {u.title},
			"department":         {u.dept},
			"mail":               {u.sam + "@" + domain},
			"userAccountControl": {"512"}, // NORMAL_ACCOUNT
			"lastLogonTimestamp": {windowsFileTime(time.Now().Add(-time.Duration(p.rnd.Intn(72)) * time.Hour))},
			"pwdLastSet":         {windowsFileTime(time.Now().Add(-time.Duration(p.rnd.Intn(200)) * 24 * time.Hour))},
			"distinguishedName":  {dn},
		})
	}

	// --- bait: kerberoastable service accounts ------------------------------
	// A service account with an SPN can have a service ticket requested by any
	// authenticated user, and that ticket is encrypted with the account's
	// password hash. Asking for one is the whole of T1558.003.
	roastable := []struct{ cn, sam, spn, note string }{
		{"svc_sql", "svc_sql", "MSSQLSvc/sql01." + domain + ":1433", "SQL Server service account"},
		{"svc_backup", "svc_backup", "HTTP/backup." + domain, "Backup service account"},
		{"svc_iis", "svc_iis", "HTTP/intranet." + domain, "IIS application pool"},
	}
	for _, u := range roastable {
		dn := fmt.Sprintf("CN=%s,OU=Service Accounts,%s", u.cn, base)
		add(dn, "kerberoastable-spn", map[string][]string{
			"objectClass":          {"top", "person", "organizationalPerson", "user"},
			"objectCategory":       {"CN=Person,CN=Schema,CN=Configuration," + base},
			"cn":                   {u.cn},
			"name":                 {u.cn},
			"sAMAccountName":       {u.sam},
			"servicePrincipalName": {u.spn},
			"description":          {u.note + " - do not disable"},
			// RC4 only and a password that has not changed in years: exactly the
			// profile an attacker looks for.
			"msDS-SupportedEncryptionTypes": {"4"},
			"userAccountControl":            {"66048"}, // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
			"pwdLastSet":                    {windowsFileTime(time.Now().Add(-4 * 365 * 24 * time.Hour))},
			"memberOf":                      {"CN=Domain Users,CN=Users," + base},
			"distinguishedName":             {dn},
		})
	}

	// --- bait: AS-REP roastable account -------------------------------------
	// Kerberos pre-authentication disabled means anyone can ask the KDC for an
	// AS-REP for this account and crack it offline. There is no operational
	// reason to look for such accounts other than to do exactly that.
	asrepDN := "CN=svc_legacy,OU=Service Accounts," + base
	add(asrepDN, "asrep-roastable", map[string][]string{
		"objectClass":        {"top", "person", "organizationalPerson", "user"},
		"objectCategory":     {"CN=Person,CN=Schema,CN=Configuration," + base},
		"cn":                 {"svc_legacy"},
		"sAMAccountName":     {"svc_legacy"},
		"description":        {"Legacy application account - preauth disabled for compatibility"},
		"userAccountControl": {"4260352"}, // DONT_REQ_PREAUTH | DONT_EXPIRE_PASSWORD
		"pwdLastSet":         {windowsFileTime(time.Now().Add(-5 * 365 * 24 * time.Hour))},
		"distinguishedName":  {asrepDN},
	})

	// --- groups --------------------------------------------------------------
	daDN := "CN=Domain Admins,CN=Users," + base
	add(daDN, "privileged-group", map[string][]string{
		"objectClass":    {"top", "group"},
		"objectCategory": {"CN=Group,CN=Schema,CN=Configuration," + base},
		"cn":             {"Domain Admins"},
		"sAMAccountName": {"Domain Admins"},
		"adminCount":     {"1"},
		"member": {
			"CN=Administrator,CN=Users," + base,
			"CN=Georgi Ivanov,OU=Users," + base,
			"CN=svc_backup,OU=Service Accounts," + base,
		},
		"distinguishedName": {daDN},
	})

	// --- computers ----------------------------------------------------------
	for _, c := range []struct{ name, os, role string }{
		{strings.ToUpper(p.Hostname), "Windows Server 2019 Standard", "domain controller"},
		{"FS01", "Windows Server 2019 Standard", "file server"},
		{"SQL01", "Windows Server 2022 Standard", "database"},
		{"FIN-WS-07", "Windows 10 Pro", "workstation"},
	} {
		dn := fmt.Sprintf("CN=%s,OU=Computers,%s", c.name, base)
		add(dn, "", map[string][]string{
			"objectClass":       {"top", "computer"},
			"objectCategory":    {"CN=Computer,CN=Schema,CN=Configuration," + base},
			"cn":                {c.name},
			"sAMAccountName":    {c.name + "$"},
			"dNSHostName":       {strings.ToLower(c.name) + "." + domain},
			"operatingSystem":   {c.os},
			"description":       {c.role},
			"distinguishedName": {dn},
		})
	}

	// --- bait: a certificate template that looks ESC1-vulnerable ------------
	// Enrollee-supplied subject plus client authentication plus enrolment for
	// ordinary users is the textbook misconfiguration. Reading these flags is
	// certificate-based privilege escalation reconnaissance and nothing else.
	tmplDN := "CN=CorpUserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + base
	add(tmplDN, "adcs-esc1-template", map[string][]string{
		"objectClass":                          {"top", "pKICertificateTemplate"},
		"cn":                                   {"CorpUserAuth"},
		"displayName":                          {"Corp User Authentication"},
		"msPKI-Certificate-Name-Flag":          {"1"},                 // ENROLLEE_SUPPLIES_SUBJECT
		"msPKI-Enrollment-Flag":                {"0"},                 // no manager approval
		"msPKI-RA-Signature":                   {"0"},                 // no authorised signatures required
		"pKIExtendedKeyUsage":                  {"1.3.6.1.5.5.7.3.2"}, // client authentication
		"msPKI-Certificate-Application-Policy": {"1.3.6.1.5.5.7.3.2"},
		"distinguishedName":                    {tmplDN},
	})
	caDN := "CN=" + netbios + "-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + base
	add(caDN, "adcs-enrollment-service", map[string][]string{
		"objectClass":          {"top", "pKIEnrollmentService"},
		"cn":                   {netbios + "-CA"},
		"dNSHostName":          {strings.ToLower(p.Hostname) + "." + domain},
		"certificateTemplates": {"CorpUserAuth", "Machine", "User", "WebServer"},
		"distinguishedName":    {caDN},
	})

	// --- bait: a LAPS-managed computer --------------------------------------
	// The local administrator password attribute is readable only by those
	// delegated to read it. Asking for it is a specific privilege hunt.
	lapsDN := "CN=FIN-WS-07,OU=Computers," + base
	for _, e := range d.Entries {
		if e.DN == lapsDN {
			e.Bait = "laps-managed"
			e.Attributes["ms-Mcs-AdmPwdExpirationTime"] = []string{windowsFileTime(time.Now().Add(24 * time.Hour))}
		}
	}

	// --- bait: a GPO with a password in it ----------------------------------
	gpoDN := "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System," + base
	add(gpoDN, "gpp-password", map[string][]string{
		"objectClass":       {"top", "groupPolicyContainer"},
		"cn":                {"{31B2F340-016D-11D2-945F-00C04FB984F9}"},
		"displayName":       {"Local Administrator Provisioning"},
		"gPCFileSysPath":    {`\\` + domain + `\SysVol\` + domain + `\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}`},
		"distinguishedName": {gpoDN},
	})

	return d
}
