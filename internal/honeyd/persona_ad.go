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
	p.AcceptAfter = 4

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
