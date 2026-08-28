package honeyd

import (
	"fmt"
	"strings"
	"time"
)

func init() { RegisterPersona("linux/fileserver", buildFileServer) }

// buildFileServer is the decoy a ransomware operator is looking for: a file
// share full of exactly the documents that make a company pay.
//
// The share is generated rather than stored. Thousands of files with plausible
// names, sizes, dates and correct magic bytes cost a few megabytes of memory,
// and an encryptor walking them behaves exactly as it would on a real share --
// which is what the detector needs in order to see it.
func buildFileServer(seed string) *Persona {
	p := &Persona{
		Name:         "linux/fileserver",
		Vertical:     "generic",
		Language:     "en",
		Domain:       "corp.local",
		OSName:       "Debian GNU/Linux 12 (bookworm)",
		OSPretty:     "Debian GNU/Linux 12 (bookworm)",
		Kernel:       "6.1.0-18-amd64",
		Arch:         "x86_64",
		SSHBanner:    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
		HTTPServer:   "nginx/1.22.1",
		FTPBanner:    "220 Corporate file service ready",
		TelnetBanner: "Debian GNU/Linux 12",
		rnd:          seedFrom(seed, "linux/fileserver"),
	}
	p.Hostname = pick(p, []string{"fs01", "fileserver01", "corp-fs-02", "shares01"})
	p.BootTime = time.Now().Add(-time.Duration(180+p.rnd.Intn(500)) * 24 * time.Hour)
	p.MOTD = linuxMOTD(p)
	p.Users = []PersonaUser{
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Gecos: "root"},
		{Name: "fileadmin", UID: 1000, GID: 1000, Home: "/home/fileadmin", Shell: "/bin/bash", Gecos: "File services,,,"},
		{Name: "backup", UID: 1001, GID: 1001, Home: "/home/backup", Shell: "/bin/bash", Gecos: "Backup agent,,,"},
	}
	p.WeakSecrets = map[string][]string{
		"backup":    {"backup", "Backup2024", "backup123"},
		"fileadmin": {"fileadmin", "Welcome1", "Company2025"},
		"root":      {"root", "toor"},
	}
	p.AcceptAfter = 3

	fs := NewVFS()
	p.FS = fs
	baseLinuxFS(p, fs)
	buildShare(p, fs)

	fs.AddFile("/root/.bash_history", strings.Join([]string{
		"smbstatus",
		"systemctl status smbd",
		"testparm -s",
		"chown -R fileadmin:finance /srv/shares/finance",
		"du -sh /srv/shares/*",
		"tail -f /var/log/samba/log.smbd",
		"exit",
	}, "\n")+"\n", "root", "root", "-rw-------", p.aged(3))
	fs.AddFile("/home/fileadmin/.bash_history", strings.Join([]string{
		"cd /srv/shares/hr", "ls -la 2026", "getfacl legal", "exit",
	}, "\n")+"\n", "fileadmin", "fileadmin", "-rw-------", p.aged(7))

	fs.AddFile("/var/log/samba/log.smbd", sambaLog(p), "root", "adm", "-rw-r-----", p.aged(1))
	fs.AddFile("/var/log/auth.log", authLog(p), "root", "adm", "-rw-r-----", p.aged(1))
	fs.AddFile("/var/log/syslog", syslogLines(p), "root", "adm", "-rw-r-----", p.aged(1))
	return p
}

// sambaLog renders the connection noise a busy share accumulates. A file server
// whose logs are empty has no users, and a file server with no users is not a
// file server.
func sambaLog(p *Persona) string {
	var b strings.Builder
	users := []string{"m.petrova", "g.ivanov", "e.dimitrova", "n.stoyanov", "fileadmin"}
	for i := 0; i < 120; i++ {
		ts := time.Now().Add(-time.Duration(p.rnd.Intn(7*86400)) * time.Second)
		user := users[p.rnd.Intn(len(users))]
		host := fmt.Sprintf("10.10.%d.%d", p.rnd.Intn(6)+20, p.rnd.Intn(200)+10)
		share := shareDepartments[p.rnd.Intn(len(shareDepartments))].name
		fmt.Fprintf(&b, "[%s, 2] ../../source3/smbd/service.c:connect_share(1234)\n",
			ts.Format("2006/01/02 15:04:05.000000"))
		fmt.Fprintf(&b, "  %s (ipv4:%s:%d) connect to service %s initially as user %s\n",
			strings.ToUpper(user), host, p.rnd.Intn(20000)+40000, share, user)
	}
	return b.String()
}

// shareDepartments drive the generated tree. Each carries the sort of document
// whose loss makes an organisation negotiate.
var shareDepartments = []struct {
	name  string
	files []string
	ext   []string
}{
	{"finance", []string{"payroll", "invoices", "budget", "forecast", "tax-return",
		"audit", "expenses", "reconciliation", "vat-report", "payments"},
		[]string{".xlsx", ".pdf", ".docx"}},
	{"hr", []string{"personnel-file", "contract", "appraisal", "sick-leave",
		"recruitment", "salary-band", "disciplinary", "onboarding"},
		[]string{".docx", ".pdf", ".xlsx"}},
	{"legal", []string{"nda", "supplier-agreement", "lease", "litigation",
		"board-minutes", "shareholder", "compliance", "dpa"},
		[]string{".docx", ".pdf"}},
	{"engineering", []string{"design-spec", "architecture", "test-plan",
		"release-notes", "incident-review", "runbook"},
		[]string{".docx", ".pdf", ".md"}},
	{"sales", []string{"pipeline", "quotation", "customer-list", "renewal",
		"proposal", "commission"},
		[]string{".xlsx", ".pptx", ".docx"}},
}

// canaryNames sort before real filenames in almost every locale, so a sweep
// that walks a directory in order hits them first. That is the point: the
// detector learns about the encryptor before it reaches anything else.
var canaryNames = []string{
	"!!!_DO_NOT_DELETE_asset_register.xlsx",
	"!!_master_password_list.docx",
	"AAA_backup_index.xlsx",
	"0000_share_inventory.pdf",
}

func buildShare(p *Persona, fs *VFS) {
	root := "/srv/shares"
	fs.Mkdir(root, "root", "root", "drwxr-xr-x", p.aged(600))

	for _, dept := range shareDepartments {
		base := root + "/" + dept.name
		fs.Mkdir(base, "root", dept.name, "drwxrws---", p.aged(500))

		// Canaries live at the top of every department directory.
		for _, c := range canaryNames {
			fs.AddCanary(base+"/"+c, documentBody(p, c), "fileadmin", dept.name,
				"-rw-rw----", p.aged(300))
		}

		// Years of subdirectories, because a share with one flat directory
		// looks like a test fixture.
		for year := 2021; year <= 2026; year++ {
			for _, quarter := range []string{"Q1", "Q2", "Q3", "Q4"} {
				if year == 2026 && quarter > "Q3" {
					continue
				}
				dir := fmt.Sprintf("%s/%d/%s", base, year, quarter)
				fs.Mkdir(dir, "fileadmin", dept.name, "drwxrws---", p.aged(400))

				// One canary per directory, not just per department: an
				// encryptor that starts deep in the tree must still trip one
				// before it gets far.
				canary := canaryNames[p.rnd.Intn(len(canaryNames))]
				fs.AddCanary(dir+"/"+canary, documentBody(p, canary),
					"fileadmin", dept.name, "-rw-rw----", p.aged(300))

				for _, stem := range dept.files {
					ext := dept.ext[p.rnd.Intn(len(dept.ext))]
					name := fmt.Sprintf("%s-%d-%s%s", stem, year, quarter, ext)
					age := time.Now().AddDate(-(2026 - year), 0, -p.rnd.Intn(80))
					fs.AddFile(dir+"/"+name, documentBody(p, name),
						"fileadmin", dept.name, "-rw-rw----", age)
				}
			}
		}
	}

	// The things an attacker looks for before encrypting.
	fs.Mkdir(root+"/IT", "root", "root", "drwxr-x---", p.aged(400))
	fs.AddToken(root+"/IT/service-accounts.xlsx",
		"Service account inventory\n\nsvc_backup / "+p.RandomToken(14)+"\n"+
			"svc_sql / "+p.RandomToken(14)+"\nsvc_scan / "+p.RandomToken(14)+"\n",
		"root", "root", "-rw-r-----", "service-account-list", p.aged(200))
	fs.AddToken(root+"/IT/vpn-config.ovpn",
		"client\ndev tun\nproto udp\nremote vpn."+p.Domain+" 1194\n"+
			"auth-user-pass\n# svc_vpn / "+p.RandomToken(16)+"\n",
		"root", "root", "-rw-r-----", "vpn-credential", p.aged(250))

	fs.Mkdir("/srv/veeam", "root", "root", "drwxr-x---", p.aged(300))
	for i := 1; i <= 6; i++ {
		fs.AddCanary(fmt.Sprintf("/srv/veeam/BackupJob_Full_%02d.vbk", i),
			"\x1f\x8b\x08\x00[veeam backup chain]", "root", "root", "-rw-r-----", p.aged(40))
	}
}

// documentBody produces content with the right magic bytes for its extension,
// so that a file which stops being a ZIP is a signal and not an artefact of
// our own generator.
func documentBody(p *Persona, name string) string {
	var b strings.Builder
	switch {
	case strings.HasSuffix(name, ".docx"), strings.HasSuffix(name, ".xlsx"),
		strings.HasSuffix(name, ".pptx"):
		b.WriteString("PK\x03\x04\x14\x00\x06\x00")
	case strings.HasSuffix(name, ".pdf"):
		b.WriteString("%PDF-1.7\n")
	}
	fmt.Fprintf(&b, "\n%s\nDepartment record. Confidential.\n", name)
	// A plausible size spread: a share where every file is the same length is
	// the sort of detail a careful operator notices.
	for i := 0; i < 8+p.rnd.Intn(60); i++ {
		fmt.Fprintf(&b, "%04d  %s  %s  %.2f\n", i,
			pick(p, []string{"approved", "pending", "review", "final", "draft"}),
			pick(p, []string{"EUR", "USD", "BGN"}), p.rnd.Float64()*90000)
	}
	return b.String()
}
