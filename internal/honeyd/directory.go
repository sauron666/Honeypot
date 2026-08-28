package honeyd

import (
	"crypto/sha256"
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
	// Accounts is the same population seen from Kerberos rather than from LDAP.
	//
	// One list, built once, because the two views have to agree: an attacker
	// who enumerates svc_sql over LDAP and then cannot roast it over Kerberos
	// has found the seam. Everything the KDC needs -- whether pre-auth is off,
	// which SPN the account carries, and the password the bait is planted with
	// -- lives here.
	Accounts []*KerbAccount
}

// KerbAccount is one principal the decoy KDC will answer for.
type KerbAccount struct {
	// SAM is the sAMAccountName, which is what an attacker types.
	SAM string
	// SPN, when set, makes the account kerberoastable: any authenticated
	// principal may ask for a ticket to it, and that ticket is encrypted with
	// this account's key.
	SPN string
	// NoPreauth mirrors DONT_REQ_PREAUTH. Such an account hands out a
	// crackable AS-REP to anyone who asks, without a password, which is the
	// whole of AS-REP roasting.
	NoPreauth bool
	// Password is what the planted bait actually cracks to. It is a real
	// password for an account that does not exist, so an attacker who cracks
	// it and then tries it anywhere in the deployment walks straight into the
	// honeytoken watcher.
	Password string
	// Machine marks a computer account, which never appears in a spray.
	Machine bool
}

// Account finds a principal by sAMAccountName, case-insensitively, because
// Kerberos names are compared that way in practice and an attacker typing
// SVC_SQL expects it to work.
func (d *Directory) Account(sam string) (*KerbAccount, bool) {
	sam = strings.TrimSpace(sam)
	if i := strings.IndexByte(sam, '@'); i > 0 {
		sam = sam[:i] // a userPrincipalName was given
	}
	for _, a := range d.Accounts {
		if strings.EqualFold(a.SAM, sam) {
			return a, true
		}
	}
	return nil, false
}

// AccountBySPN finds the account that owns a service principal name.
func (d *Directory) AccountBySPN(spn string) (*KerbAccount, bool) {
	for _, a := range d.Accounts {
		if a.SPN != "" && strings.EqualFold(a.SPN, spn) {
			return a, true
		}
	}
	return nil, false
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
		// Ordinary users exist in Kerberos too, or a spray would find nothing
		// and the attacker would conclude the KDC is fake. Their passwords are
		// planted the same way, but pre-authentication is on, so the only way
		// to learn one is to guess it -- and every guess is recorded.
		d.Accounts = append(d.Accounts, &KerbAccount{
			SAM: u.sam, Password: plantedPassword(p, u.sam),
		})
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
		d.Accounts = append(d.Accounts, &KerbAccount{
			SAM: u.sam, SPN: u.spn, Password: plantedPassword(p, u.sam),
		})
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
	d.Accounts = append(d.Accounts, &KerbAccount{
		SAM: "svc_legacy", NoPreauth: true, Password: plantedPassword(p, "svc_legacy"),
	})
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

// plantedPassword mints the password a piece of Kerberos bait cracks to.
//
// It has to be crackable. A blob whose password is a random 32-character string
// would survive every wordlist, and an attacker whose hashcat run comes back
// empty on a "neglected service account with RC4 only and a password unchanged
// for four years" has learnt something true about the account: it is not real.
// So the shape is the shape of a password people actually choose, and the
// wordlist finds it in seconds.
//
// What it unlocks is nothing. The value of the crack to us is the reuse: the
// attacker takes it to SSH, SMB or MSSQL somewhere in the deployment, and the
// honeytoken watcher joins the offline crack to the online attempt.
func plantedPassword(p *Persona, account string) string {
	words := []string{"Summer", "Winter", "Autumn", "Spring", "Welcome", "Password", "Backup", "Service"}
	suffix := []string{"!", "1!", "123", "#1", "2019!", "2020!", "$", "01!"}
	key := p.Seed + "|" + p.Domain + "|" + account
	w := words[int(stableByte(key, 0))%len(words)]
	n := 2015 + int(stableByte(key, 1))%10
	sfx := suffix[int(stableByte(key, 2))%len(suffix)]
	return fmt.Sprintf("%s%d%s", w, n, sfx)
}

// stableByte derives a byte from a key and an index. It hashes the deployment
// seed with the account name rather than drawing from the persona RNG, for two
// reasons: the password for svc_sql must not change when an unrelated entry is
// added above it in the directory -- an attacker who roasts the same account
// twice and gets a different answer has been told the decoy regenerates -- and
// two installations must never plant the same password, or the bait itself
// becomes a signature that identifies MIRAGE.
func stableByte(s string, i int) byte {
	sum := sha256.Sum256([]byte("mirage-krb|" + s))
	return sum[i%len(sum)]
}
