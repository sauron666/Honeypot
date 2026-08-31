// Package file name note: this must not be called persona_windows.go. Go reads
// a _windows suffix as an implicit build constraint and would compile it only
// on Windows, silently dropping the domain controller persona everywhere else.
package honeyd

import (
	"fmt"
	"strings"
	"time"
)

func init() { RegisterPersona("windows/dc", buildWindowsDC) }

// buildWindowsDC is a domain controller: the object every intrusion into a
// Windows estate converges on.
//
// It carries no shell -- there is nothing convincing to fake there -- but it
// answers LDAP and SMB, which is where the interesting questions get asked.
func buildWindowsDC(seed string) *Persona {
	p := &Persona{
		Seed:         seed,
		Name:         "windows/dc",
		Vertical:     "generic",
		Language:     "en",
		Domain:       "corp.local",
		OSName:       "Windows Server 2019 Standard",
		OSPretty:     "Windows Server 2019 Standard 10.0.17763",
		Kernel:       "10.0.17763",
		Arch:         "x86_64",
		SSHBanner:    "SSH-2.0-OpenSSH_for_Windows_8.1",
		HTTPServer:   "Microsoft-IIS/10.0",
		FTPBanner:    "220 Microsoft FTP Service",
		TelnetBanner: "Microsoft Telnet Service",
		rnd:          seedFrom(seed, "windows/dc"),
	}
	p.Hostname = pick(p, []string{"DC01", "DC02", "CORP-DC-01", "ADDS01"})
	p.BootTime = time.Now().Add(-time.Duration(120+p.rnd.Intn(400)) * 24 * time.Hour)
	p.MOTD = "Microsoft Windows [Version 10.0.17763.5576]\r\n(c) Microsoft Corporation. All rights reserved.\r\n"

	p.Users = []PersonaUser{
		{Name: "Administrator", UID: 500, GID: 513, Home: `C:\Users\Administrator`, Shell: "cmd.exe", Gecos: "Built-in account"},
		{Name: "svc_backup", UID: 1104, GID: 513, Home: `C:\Users\svc_backup`, Shell: "cmd.exe", Gecos: "Backup service"},
		{Name: "g.ivanov", UID: 1108, GID: 513, Home: `C:\Users\g.ivanov`, Shell: "cmd.exe", Gecos: "Systems Engineer"},
	}
	p.WeakSecrets = map[string][]string{
		"Administrator": {"P@ssw0rd", "Welcome1", "Passw0rd!"},
		"svc_backup":    {"Backup2024!", "Summer2025!"},
		"*":             {"Password1"},
	}

	fs := NewVFS()
	p.FS = fs
	buildWindowsFS(p, fs)
	return p
}

// buildWindowsFS lays down the paths a Windows recon script looks at. It is
// deliberately small: the value of this persona is its directory, not its disk.
func buildWindowsFS(p *Persona, fs *VFS) {
	old := p.aged(700)
	for _, d := range []string{
		"C:", "C:/Windows", "C:/Windows/System32", "C:/Windows/NTDS",
		"C:/Windows/SYSVOL", "C:/Program Files", "C:/Users", "C:/Users/Administrator",
	} {
		fs.Mkdir(d, "Administrators", "SYSTEM", "drwxr-x---", old)
	}

	sysvol := fmt.Sprintf("C:/Windows/SYSVOL/sysvol/%s/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/Groups", p.Domain)
	fs.Mkdir(sysvol, "Administrators", "SYSTEM", "drwxr-x---", p.aged(400))
	// A Group Policy Preferences password: the classic finding, and the
	// encryption key for it has been public since 2012.
	fs.AddToken(sysvol+"/Groups.xml", groupsXML(p.RandomToken(44)),
		"Administrators", "SYSTEM", "-rw-r-----", "gpp-cpassword", p.aged(400))

	fs.AddFile("C:/Windows/NTDS/ntds.dit", "[extensible storage engine database]",
		"SYSTEM", "SYSTEM", "-rw-------", p.aged(1))
	fs.AddFile("C:/Users/Administrator/Desktop/passwords.txt.lnk",
		"[shortcut]", "Administrator", "Administrators", "-rw-r-----", p.aged(90))

	// A domain controller that nobody has ever administered is not a domain
	// controller. PowerShell keeps its history here, and it is the first file
	// anyone reads after landing on a Windows host.
	fs.AddFile("C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
		strings.Join([]string{
			"Get-ADUser -Filter * -Properties LastLogonDate | Select Name,LastLogonDate",
			"repadmin /replsummary",
			"dcdiag /test:replications",
			"Get-ADGroupMember 'Domain Admins'",
			"Set-ADAccountPassword -Identity svc_backup",
			"Get-GPOReport -All -ReportType Html -Path C:\\temp\\gpo.html",
			"Restart-Service ADWS",
			"exit",
		}, "\r\n")+"\r\n",
		"Administrator", "Administrators", "-rw-------", p.aged(4))

	fs.Mkdir("C:/Windows/System32/winevt/Logs", "SYSTEM", "SYSTEM", "drwxr-x---", p.aged(600))
	fs.AddFile("C:/Windows/System32/winevt/Logs/Security.evtx", securityEventLog(p),
		"SYSTEM", "SYSTEM", "-rw-------", p.aged(1))
	fs.AddFile("C:/Windows/System32/winevt/Logs/System.evtx", systemEventLog(p),
		"SYSTEM", "SYSTEM", "-rw-------", p.aged(1))
}

// securityEventLog renders the authentication traffic a domain controller sees
// constantly. An empty security log on a DC is impossible.
func securityEventLog(p *Persona) string {
	var b strings.Builder
	users := []string{"m.petrova", "g.ivanov", "e.dimitrova", "n.stoyanov", "svc_sql", "svc_backup"}
	for i := 0; i < 200; i++ {
		ts := time.Now().Add(-time.Duration(p.rnd.Intn(3*86400)) * time.Second)
		user := users[p.rnd.Intn(len(users))]
		host := fmt.Sprintf("10.10.%d.%d", p.rnd.Intn(6)+20, p.rnd.Intn(200)+10)
		id := pick(p, []string{"4624", "4768", "4769", "4776", "4634"})
		fmt.Fprintf(&b, "%s EventID=%s Account=%s Workstation=%s LogonType=3\n",
			ts.Format("2006-01-02T15:04:05.000Z"), id, user, host)
	}
	return b.String()
}

// systemEventLog renders service and replication noise.
func systemEventLog(p *Persona) string {
	var b strings.Builder
	for i := 0; i < 80; i++ {
		ts := time.Now().Add(-time.Duration(p.rnd.Intn(5*86400)) * time.Second)
		msg := pick(p, []string{
			"EventID=1074 The process wininit.exe has initiated the restart of computer",
			"EventID=7036 The Windows Time service entered the running state",
			"EventID=1704 Security policy in the Group Policy objects has been applied successfully",
			"EventID=13 The time provider NtpClient is currently receiving valid time data",
			"EventID=1129 Could not apply Group Policy: no domain controller available",
		})
		fmt.Fprintf(&b, "%s %s\n", ts.Format("2006-01-02T15:04:05.000Z"), msg)
	}
	return b.String()
}

// groupsXML renders a Group Policy Preferences file carrying a cpassword.
//
// This is the classic finding: the AES key Microsoft used for these has been
// public since 2012, so anyone who reads the file can decrypt it. Ours decrypts
// to nothing, and reading it is the signal.
func groupsXML(cpassword string) string {
	const tmpl = `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="0">
    <Properties action="U" newName="" fullName="Local Administrator" description=""
      cpassword="%s" changeLogon="0" noChange="1" neverExpires="1"
      acctDisabled="0" userName="LocalAdmin"/>
  </User>
</Groups>
`
	return fmt.Sprintf(tmpl, cpassword)
}

// windowsPersonaNames lists the personas that describe Windows hosts, for the
// places that need to know not to offer a Unix shell.
func isWindowsPersona(name string) bool { return strings.HasPrefix(name, "windows/") }
