package honeyd

import (
	"fmt"
	"strings"
	"time"
)

func init() {
	RegisterPersona("linux/web", buildLinuxWeb)
	RegisterPersona("linux/db", buildLinuxDB)
	RegisterPersona("linux/backup", buildLinuxBackup)
}

// buildLinuxWeb is a Debian web server: the most-scanned machine on any
// network, and therefore the most useful decoy to have first.
func buildLinuxWeb(seed string) *Persona {
	p := &Persona{
		Name:         "linux/web",
		Vertical:     "generic",
		Language:     "en",
		Domain:       "corp.local",
		OSName:       "Debian GNU/Linux 12 (bookworm)",
		OSPretty:     "Debian GNU/Linux 12 (bookworm)",
		Kernel:       "6.1.0-18-amd64",
		Arch:         "x86_64",
		SSHBanner:    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
		HTTPServer:   "nginx/1.22.1",
		FTPBanner:    "220 (vsFTPd 3.0.3)",
		TelnetBanner: "Debian GNU/Linux 12",
		rnd:          seedFrom(seed, "linux/web"),
	}
	p.Hostname = pick(p, []string{"web01", "srv-web-01", "app-prod-02", "www2"})
	p.BootTime = time.Now().Add(-time.Duration(90+p.rnd.Intn(400)) * 24 * time.Hour)
	p.MOTD = linuxMOTD(p)

	p.Users = []PersonaUser{
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Gecos: "root"},
		{Name: "deploy", UID: 1000, GID: 1000, Home: "/home/deploy", Shell: "/bin/bash", Gecos: "Deployment user,,,"},
		{Name: "backup", UID: 1001, GID: 1001, Home: "/home/backup", Shell: "/bin/bash", Gecos: "Backup agent,,,"},
	}
	// Two ways in: a planted weak password, and eventual acceptance so a
	// brute-force run that never guesses it still gets observed inside.
	p.WeakSecrets = map[string][]string{
		"root":   {"root", "toor", "admin123", "P@ssw0rd"},
		"deploy": {"deploy", "deploy123", "Summer2024!"},
		"*":      {"123456", "password"},
	}
	p.AcceptAfter = 4

	fs := NewVFS()
	p.FS = fs
	baseLinuxFS(p, fs)

	fs.Mkdir("/var/www/html", "www-data", "www-data", "", p.aged(300))
	fs.AddFile("/var/www/html/index.html",
		"<!doctype html><html><head><title>"+p.Hostname+"</title></head>\n<body><h1>It works</h1></body></html>\n",
		"www-data", "www-data", "-rw-r--r--", p.aged(300))
	fs.AddFile("/etc/nginx/nginx.conf", nginxConf(p), "root", "root", "-rw-r--r--", p.aged(280))
	fs.AddFile("/etc/nginx/sites-enabled/default", nginxSite(p), "root", "root", "-rw-r--r--", p.aged(120))

	// Baited application config: a database credential pointing at a decoy DB.
	dbPass := p.RandomToken(16)
	fs.AddToken("/var/www/html/.env",
		fmt.Sprintf("APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:%s\n"+
			"DB_CONNECTION=mysql\nDB_HOST=db01.%s\nDB_PORT=3306\nDB_DATABASE=billing\n"+
			"DB_USERNAME=billing_app\nDB_PASSWORD=%s\n"+
			"REDIS_HOST=cache01.%s\nMAIL_HOST=smtp.%s\n",
			p.RandomToken(43), p.Domain, dbPass, p.Domain, p.Domain),
		"www-data", "www-data", "-rw-r-----", "app-db-credential", p.aged(90))

	fs.AddToken("/root/.ssh/id_rsa", fakePrivateKey(p), "root", "root", "-rw-------", "root-ssh-key", p.aged(400))
	fs.AddFile("/root/.ssh/authorized_keys", fakePublicKey(p, "root@"+p.Hostname), "root", "root", "-rw-------", p.aged(400))
	fs.AddFile("/root/.bash_history", strings.Join([]string{
		"systemctl status nginx",
		"tail -f /var/log/nginx/error.log",
		"cd /var/www/html",
		"git pull",
		"systemctl reload nginx",
		"df -h",
		"apt update && apt upgrade -y",
		"ssh backup@nas01." + p.Domain,
		"mysql -h db01." + p.Domain + " -u billing_app -p billing",
		"exit",
	}, "\n")+"\n", "root", "root", "-rw-------", p.aged(3))

	fs.AddFile("/home/deploy/.bash_history", strings.Join([]string{
		"cd /var/www/html", "git status", "./deploy.sh production", "sudo systemctl reload nginx", "exit",
	}, "\n")+"\n", "deploy", "deploy", "-rw-------", p.aged(6))

	fs.AddFile("/var/log/nginx/access.log", accessLog(p), "www-data", "adm", "-rw-r-----", p.aged(1))
	fs.AddFile("/var/log/auth.log", authLog(p), "root", "adm", "-rw-r-----", p.aged(1))
	return p
}

// buildLinuxDB is a database server: what an attacker pivots to after finding
// the credentials planted on the web decoy.
func buildLinuxDB(seed string) *Persona {
	p := &Persona{
		Name:         "linux/db",
		Vertical:     "generic",
		Language:     "en",
		Domain:       "corp.local",
		OSName:       "Ubuntu 22.04.4 LTS",
		OSPretty:     "Ubuntu 22.04.4 LTS",
		Kernel:       "5.15.0-105-generic",
		Arch:         "x86_64",
		SSHBanner:    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7",
		HTTPServer:   "Apache/2.4.52 (Ubuntu)",
		FTPBanner:    "220 ProFTPD Server (Debian)",
		TelnetBanner: "Ubuntu 22.04.4 LTS",
		rnd:          seedFrom(seed, "linux/db"),
	}
	p.Hostname = pick(p, []string{"db01", "sql-prod-01", "mysql02", "pgsql01"})
	p.BootTime = time.Now().Add(-time.Duration(150+p.rnd.Intn(500)) * 24 * time.Hour)
	p.MOTD = linuxMOTD(p)
	p.Users = []PersonaUser{
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Gecos: "root"},
		{Name: "dba", UID: 1000, GID: 1000, Home: "/home/dba", Shell: "/bin/bash", Gecos: "Database admin,,,"},
		{Name: "mysql", UID: 111, GID: 115, Home: "/nonexistent", Shell: "/bin/false", Gecos: "MySQL Server,,,"},
	}
	p.WeakSecrets = map[string][]string{
		"root": {"root", "mysql", "Passw0rd!"},
		"dba":  {"dba", "dba123", "Database1"},
		"*":    {"123456"},
	}
	p.AcceptAfter = 4

	fs := NewVFS()
	p.FS = fs
	baseLinuxFS(p, fs)

	rootPass := p.RandomToken(18)
	fs.AddToken("/etc/mysql/my.cnf",
		"[client]\nhost=localhost\nuser=root\npassword="+rootPass+"\n\n"+
			"[mysqld]\nbind-address=0.0.0.0\ndatadir=/var/lib/mysql\n"+
			"max_connections=300\ninnodb_buffer_pool_size=4G\n",
		"root", "root", "-rw-r-----", "mysql-root-credential", p.aged(200))
	fs.AddFile("/etc/mysql/mysql.conf.d/mysqld.cnf", "[mysqld]\nbind-address = 0.0.0.0\nport = 3306\n",
		"root", "root", "-rw-r--r--", p.aged(200))
	fs.Mkdir("/var/lib/mysql/billing", "mysql", "mysql", "drwx------", p.aged(200))
	fs.AddFile("/var/backups/billing-nightly.sql.gz", "\x1f\x8b\x08\x00[binary dump]", "root", "root", "-rw-r-----", p.aged(1))
	fs.AddFile("/root/.mysql_history", strings.Join([]string{
		"show databases;", "use billing;", "show tables;",
		"select count(*) from invoices;", "flush privileges;",
	}, "\n")+"\n", "root", "root", "-rw-------", p.aged(9))
	fs.AddFile("/root/.bash_history", strings.Join([]string{
		"systemctl status mysql", "mysql -u root -p", "mysqldump --all-databases > /var/backups/all.sql",
		"du -sh /var/lib/mysql", "exit",
	}, "\n")+"\n", "root", "root", "-rw-------", p.aged(4))

	fs.AddFile("/var/log/mysql/error.log", mysqlErrorLog(p), "mysql", "adm", "-rw-r-----", p.aged(1))
	fs.AddFile("/var/log/auth.log", authLog(p), "root", "adm", "-rw-r-----", p.aged(1))
	fs.AddFile("/var/log/syslog", syslogLines(p), "root", "adm", "-rw-r-----", p.aged(1))
	return p
}

// mysqlErrorLog renders the sort of noise a long-running database accumulates.
func mysqlErrorLog(p *Persona) string {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		ts := time.Now().Add(-time.Duration(p.rnd.Intn(72)) * time.Hour)
		msg := pick(p, []string{
			"[Note] Aborted connection to db: 'billing' user: 'billing_app' (Got timeout reading communication packets)",
			"[Warning] Access denied for user 'root'@'10.10.22.14' (using password: YES)",
			"[Note] InnoDB: page_cleaner: 1000ms intended loop took 4213ms",
			"[Note] Event Scheduler: Loaded 0 events",
		})
		fmt.Fprintf(&b, "%s 0 %s\n", ts.Format("2006-01-02T15:04:05.000000Z"), msg)
	}
	return b.String()
}

// syslogLines renders general system noise.
func syslogLines(p *Persona) string {
	var b strings.Builder
	for i := 0; i < 60; i++ {
		ts := time.Now().Add(-time.Duration(p.rnd.Intn(86400)) * time.Second)
		msg := pick(p, []string{
			"systemd[1]: Started Daily apt download activities.",
			"CRON[%d]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
			"systemd[1]: logrotate.service: Succeeded.",
			"kernel: [UFW BLOCK] IN=ens18 OUT= SRC=10.10.22.9 DST=10.66.0.10 PROTO=TCP SPT=51234 DPT=23",
			"chronyd[812]: Selected source 10.10.0.10",
		})
		fmt.Fprintf(&b, "%s %s %s\n", ts.Format("Jan  2 15:04:05"), p.Hostname,
			strings.ReplaceAll(msg, "%d", fmt.Sprint(p.rnd.Intn(30000)+1000)))
	}
	return b.String()
}

// buildLinuxBackup is a backup host. Ransomware operators look for these
// before anything else, which makes it the highest-value decoy in the fleet.
func buildLinuxBackup(seed string) *Persona {
	p := &Persona{
		Name:         "linux/backup",
		Vertical:     "generic",
		Language:     "en",
		Domain:       "corp.local",
		OSName:       "Debian GNU/Linux 11 (bullseye)",
		OSPretty:     "Debian GNU/Linux 11 (bullseye)",
		Kernel:       "5.10.0-28-amd64",
		Arch:         "x86_64",
		SSHBanner:    "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
		HTTPServer:   "nginx/1.18.0",
		FTPBanner:    "220 NAS FTP service ready",
		TelnetBanner: "Debian GNU/Linux 11",
		rnd:          seedFrom(seed, "linux/backup"),
	}
	p.Hostname = pick(p, []string{"nas01", "backup01", "veeam-repo", "storage02"})
	p.BootTime = time.Now().Add(-time.Duration(200+p.rnd.Intn(600)) * 24 * time.Hour)
	p.MOTD = linuxMOTD(p)
	p.Users = []PersonaUser{
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Gecos: "root"},
		{Name: "backup", UID: 1000, GID: 1000, Home: "/home/backup", Shell: "/bin/bash", Gecos: "Backup service,,,"},
	}
	p.WeakSecrets = map[string][]string{
		"backup": {"backup", "backup123", "Backup2024"},
		"root":   {"root", "nas", "admin"},
	}
	p.AcceptAfter = 3

	fs := NewVFS()
	p.FS = fs
	baseLinuxFS(p, fs)

	for _, dir := range []string{"finance", "hr", "legal", "engineering"} {
		fs.Mkdir("/srv/backup/"+dir, "backup", "backup", "drwxr-x---", p.aged(60))
	}
	for _, f := range []struct{ path, desc string }{
		{"/srv/backup/finance/payroll-2025-Q1.xlsx.gz", "payroll"},
		{"/srv/backup/finance/invoices-2025.sql.gz", "invoices"},
		{"/srv/backup/hr/personnel-records.tar.gz", "personnel"},
		{"/srv/backup/legal/contracts-archive.zip", "contracts"},
		{"/srv/backup/engineering/source-nightly.tar.gz", "source"},
	} {
		fs.AddToken(f.path, "\x1f\x8b\x08\x00[archive: "+f.desc+"]", "backup", "backup", "-rw-r-----",
			"backup-archive:"+f.desc, p.aged(30))
	}
	fs.AddFile("/etc/cron.d/backup",
		"0 2 * * * backup /usr/local/bin/nightly-backup.sh >> /var/log/backup.log 2>&1\n",
		"root", "root", "-rw-r--r--", p.aged(300))
	fs.AddFile("/root/.bash_history", strings.Join([]string{
		"df -h /srv/backup",
		"rsync -av --progress /srv/backup/finance/ /mnt/offsite/finance/",
		"tail -f /var/log/backup.log",
		"systemctl status rsync",
		"du -sh /srv/backup/*",
		"crontab -l",
		"exit",
	}, "\n")+"\n", "root", "root", "-rw-------", p.aged(2))
	fs.AddFile("/home/backup/.bash_history", strings.Join([]string{
		"cd /srv/backup", "ls -la", "./verify-archives.sh", "exit",
	}, "\n")+"\n", "backup", "backup", "-rw-------", p.aged(5))
	fs.AddFile("/var/log/backup.log", backupLog(p), "root", "adm", "-rw-r-----", p.aged(1))
	fs.AddFile("/var/log/auth.log", authLog(p), "root", "adm", "-rw-r-----", p.aged(1))
	fs.AddFile("/var/log/syslog", syslogLines(p), "root", "adm", "-rw-r-----", p.aged(1))

	fs.AddToken("/usr/local/bin/nightly-backup.sh",
		"#!/bin/bash\n# nightly backup to offsite\nRSYNC_PASSWORD='"+p.RandomToken(14)+"'\n"+
			"rsync -az --delete /srv/backup/ offsite@backup-remote."+p.Domain+"::vault/\n",
		"root", "root", "-rwxr-x---", "offsite-rsync-credential", p.aged(300))
	return p
}

// baseLinuxFS lays down the directories and files every Linux host has. Getting
// these right is what makes `ls /` and `cat /etc/os-release` unremarkable.
func baseLinuxFS(p *Persona, fs *VFS) {
	old := p.aged(700)
	for _, d := range []string{
		"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/media", "/mnt",
		"/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp",
		"/usr", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/share",
		"/var", "/var/log", "/var/tmp", "/var/backups", "/var/spool",
	} {
		fs.Mkdir(d, "root", "root", "", old)
	}
	fs.Mkdir("/root", "root", "root", "drwx------", p.aged(30))

	for _, u := range p.Users {
		if u.UID >= 1000 && u.Home != "" && u.Home != "/nonexistent" {
			fs.Mkdir(u.Home, u.Name, u.Name, "drwxr-xr-x", p.aged(200))
			fs.Mkdir(u.Home+"/.ssh", u.Name, u.Name, "drwx------", p.aged(200))
		}
	}

	fs.AddFile("/etc/hostname", p.Hostname+"\n", "root", "root", "-rw-r--r--", p.aged(600))
	fs.AddFile("/etc/hosts",
		fmt.Sprintf("127.0.0.1\tlocalhost\n127.0.1.1\t%s.%s\t%s\n\n"+
			"::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\n",
			p.Hostname, p.Domain, p.Hostname),
		"root", "root", "-rw-r--r--", p.aged(600))
	fs.AddFile("/etc/os-release", osRelease(p), "root", "root", "-rw-r--r--", p.aged(600))
	fs.AddFile("/etc/passwd", p.passwdFile(), "root", "root", "-rw-r--r--", p.aged(200))
	fs.AddFile("/etc/shadow", p.shadowFile(), "root", "shadow", "-rw-r-----", p.aged(200))
	fs.AddFile("/etc/group", "root:x:0:\nadm:x:4:\nsudo:x:27:"+p.Users[len(p.Users)-1].Name+"\nwww-data:x:33:\n",
		"root", "root", "-rw-r--r--", p.aged(200))
	fs.AddFile("/etc/resolv.conf",
		"nameserver 10.10.0.10\nnameserver 10.10.0.11\nsearch "+p.Domain+"\n",
		"root", "root", "-rw-r--r--", p.aged(150))
	fs.AddFile("/etc/fstab",
		"UUID=1c5b8f2a-91d3-4e77-b0c4-5d9e3a1f7b62 /     ext4  errors=remount-ro 0 1\n"+
			"UUID=8f31a4d0-2b7c-42e8-9a1f-6c0b5e2d84a3 /home ext4  defaults          0 2\n",
		"root", "root", "-rw-r--r--", p.aged(600))
	fs.AddFile("/etc/crontab",
		"SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"+
			"17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"+
			"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n",
		"root", "root", "-rw-r--r--", p.aged(600))
	fs.AddFile("/etc/issue", p.OSName+" \\n \\l\n\n", "root", "root", "-rw-r--r--", p.aged(600))
	fs.AddFile("/etc/machine-id", p.RandomToken(32)+"\n", "root", "root", "-rw-r--r--", p.aged(700))
	fs.AddFile("/proc/version",
		fmt.Sprintf("Linux version %s (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14)) #1 SMP PREEMPT_DYNAMIC\n", p.Kernel),
		"root", "root", "-r--r--r--", p.BootTime)
}

func osRelease(p *Persona) string {
	id, ver := "debian", "12"
	if strings.Contains(strings.ToLower(p.OSName), "ubuntu") {
		id, ver = "ubuntu", "22.04"
	}
	return fmt.Sprintf("PRETTY_NAME=\"%s\"\nNAME=\"%s\"\nVERSION_ID=\"%s\"\nID=%s\n"+
		"HOME_URL=\"https://www.%s.org/\"\nSUPPORT_URL=\"https://www.%s.org/support\"\n",
		p.OSPretty, strings.Split(p.OSName, " ")[0], ver, id, id, id)
}

func linuxMOTD(p *Persona) string {
	return fmt.Sprintf("Linux %s %s #1 SMP %s\n\n"+
		"The programs included with the %s system are free software;\n"+
		"the exact distribution terms for each program are described in the\n"+
		"individual files in /usr/share/doc/*/copyright.\n\n"+
		"%s comes with ABSOLUTELY NO WARRANTY, to the extent\npermitted by applicable law.\n",
		p.Hostname, p.Kernel, p.Arch, strings.Split(p.OSName, " ")[0], strings.Split(p.OSName, " ")[0])
}

func nginxConf(p *Persona) string {
	return "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\n\n" +
		"events { worker_connections 768; }\n\nhttp {\n\tsendfile on;\n\tkeepalive_timeout 65;\n" +
		"\tinclude /etc/nginx/mime.types;\n\tdefault_type application/octet-stream;\n" +
		"\taccess_log /var/log/nginx/access.log;\n\terror_log /var/log/nginx/error.log;\n" +
		"\tinclude /etc/nginx/sites-enabled/*;\n}\n"
}

func nginxSite(p *Persona) string {
	return fmt.Sprintf("server {\n\tlisten 80 default_server;\n\troot /var/www/html;\n"+
		"\tindex index.html index.php;\n\tserver_name %s.%s;\n\n"+
		"\tlocation / { try_files $uri $uri/ =404; }\n"+
		"\tlocation ~ \\.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php8.1-fpm.sock; }\n}\n",
		p.Hostname, p.Domain)
}

func accessLog(p *Persona) string {
	var b strings.Builder
	paths := []string{"/", "/index.html", "/api/health", "/static/app.css", "/favicon.ico", "/api/v1/status"}
	for i := 0; i < 40; i++ {
		ts := time.Now().Add(-time.Duration(p.rnd.Intn(86400)) * time.Second)
		b.WriteString(fmt.Sprintf("10.10.%d.%d - - [%s] \"GET %s HTTP/1.1\" 200 %d \"-\" \"Mozilla/5.0\"\n",
			p.rnd.Intn(6)+20, p.rnd.Intn(240)+2, ts.Format("02/Jan/2006:15:04:05 -0700"),
			paths[p.rnd.Intn(len(paths))], p.rnd.Intn(9000)+200))
	}
	return b.String()
}

func authLog(p *Persona) string {
	var b strings.Builder
	for i := 0; i < 25; i++ {
		ts := time.Now().Add(-time.Duration(p.rnd.Intn(86400)) * time.Second)
		b.WriteString(fmt.Sprintf("%s %s CRON[%d]: pam_unix(cron:session): session opened for user root(uid=0)\n",
			ts.Format("Jan  2 15:04:05"), p.Hostname, p.rnd.Intn(30000)+1000))
	}
	return b.String()
}

// backupLog renders a nightly job's output over the last weeks.
func backupLog(p *Persona) string {
	var b strings.Builder
	for day := 30; day > 0; day-- {
		ts := time.Now().AddDate(0, 0, -day)
		files := p.rnd.Intn(4000) + 12000
		bytes := p.rnd.Intn(40) + 60
		fmt.Fprintf(&b, "%s starting nightly backup\n", ts.Format("2006-01-02 02:00:01"))
		fmt.Fprintf(&b, "%s sent %d files, %d.%d GB\n",
			ts.Format("2006-01-02 02:4"+fmt.Sprint(p.rnd.Intn(9))+":12"), files, bytes, p.rnd.Intn(10))
		fmt.Fprintf(&b, "%s completed with 0 errors\n", ts.Format("2006-01-02 02:52:30"))
	}
	return b.String()
}

func fakePrivateKey(p *Persona) string {
	var b strings.Builder
	b.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for i := 0; i < 25; i++ {
		b.WriteString(p.RandomToken(70) + "\n")
	}
	b.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
	return b.String()
}

func fakePublicKey(p *Persona, comment string) string {
	return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + p.RandomToken(43) + " " + comment + "\n"
}

func pick(p *Persona, options []string) string { return options[p.rnd.Intn(len(options))] }
