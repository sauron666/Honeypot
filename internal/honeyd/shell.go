package honeyd

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// Shell is the fake interactive shell served to an attacker who authenticates
// to an SSH or telnet decoy.
//
// Containment: nothing here executes anything. Commands are parsed, classified,
// recorded and answered from the persona's virtual filesystem. A command that
// would reach the network (wget, curl, ssh, nc) produces a plausible answer and
// an IOC event -- never a packet. See docs/04.
type Shell struct {
	p       *Persona
	s       *Session
	user    string
	cwd     string
	env     map[string]string
	history []string
	// downloads collects every URL the attacker tried to fetch; these are the
	// second-stage payload locations and are worth more than the shell itself.
	downloads []string
	// written is this session's overlay: files and directories the attacker
	// creates (redirection, touch, mkdir). It sits on top of the read-only
	// persona VFS so writes survive within the session -- a decoy that silently
	// drops an SSH key or a webshell is an obvious tell -- without ever mutating
	// the shared filesystem. The shell runs in one goroutine, so no lock is
	// needed; keeping the persona VFS immutable keeps every other reader safe.
	written map[string]*ovNode
}

// ovNode is one attacker-created filesystem entry in the session overlay.
type ovNode struct {
	dir     bool
	content string
	owner   string
	mtime   time.Time
}

// NewShell starts a shell session for a user.
func NewShell(p *Persona, s *Session, user string) *Shell {
	home := "/root"
	for _, u := range p.Users {
		if u.Name == user {
			home = u.Home
		}
	}
	return &Shell{
		p: p, s: s, user: user, cwd: home,
		written: map[string]*ovNode{},
		env: map[string]string{
			"HOME": home, "USER": user, "LOGNAME": user, "SHELL": "/bin/bash",
			"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"TERM": "xterm-256color", "PWD": home, "HOSTNAME": p.Hostname,
		},
	}
}

// Prompt renders the shell prompt.
func (sh *Shell) Prompt() string {
	sym := "$"
	if sh.user == "root" {
		sym = "#"
	}
	cwd := sh.cwd
	if cwd == sh.env["HOME"] {
		cwd = "~"
	} else if base := path.Base(cwd); cwd != "/" {
		cwd = base
	}
	return fmt.Sprintf("%s@%s:%s%s ", sh.user, sh.p.Hostname, cwd, sym)
}

// Banner is what the decoy prints on login.
func (sh *Shell) Banner() string {
	last := time.Now().Add(-time.Duration(sh.p.rnd.Intn(72)+2) * time.Hour)
	return sh.p.MOTD + fmt.Sprintf("\nLast login: %s from 10.10.%d.%d\n",
		last.Format("Mon Jan  2 15:04:05 2006"), sh.p.rnd.Intn(6)+20, sh.p.rnd.Intn(200)+10)
}

// Downloads returns the URLs the attacker attempted to fetch.
func (sh *Shell) Downloads() []string { return append([]string(nil), sh.downloads...) }

var urlPattern = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[^\s'"|;)]+`)

// Execute runs one command line and returns the output plus whether the session
// should end.
func (sh *Shell) Execute(line string) (output string, exit bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	sh.history = append(sh.history, line)

	sev, techniques := classify(line)
	sh.s.Command(line, sev, techniques...)

	// Any URL in any command is a second-stage indicator, whatever the command.
	for _, u := range urlPattern.FindAllString(line, -1) {
		sh.downloads = append(sh.downloads, u)
		e := sh.s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
			WithMessage("attacker referenced remote payload: %s", u).
			WithAttack(event.Technique{Tactic: "TA0011", Technique: "T1105", Name: "Ingress Tool Transfer"})
		e.Set("url", u).Set("command", line).Set("ioc_type", "url")
		sh.s.Emit(e)
	}

	// Compound commands: run each part so a chained one-liner is still parsed.
	if parts := splitCompound(line); len(parts) > 1 {
		var b strings.Builder
		for _, part := range parts {
			out, ex := sh.runOne(part)
			b.WriteString(out)
			if ex {
				return b.String(), true
			}
		}
		return b.String(), false
	}
	return sh.runOne(line)
}

// splitCompound breaks on ;, && and || without pretending to be a real parser.
func splitCompound(line string) []string {
	repl := strings.NewReplacer("&&", "\x00", "||", "\x00", ";", "\x00")
	var out []string
	for _, p := range strings.Split(repl.Replace(line), "\x00") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runOne executes one simple command, honouring output redirection (> and >>).
// A redirected command's stdout lands in the session overlay instead of the
// terminal, so `echo pwned > /tmp/x` followed by `cat /tmp/x` behaves like a
// real host -- the write-then-read probe every honeypot detector runs.
func (sh *Shell) runOne(line string) (string, bool) {
	line, redir := parseRedirect(line)
	out, exit := sh.dispatch(line)
	if redir != nil {
		return sh.applyRedirect(redir, out), exit
	}
	return out, exit
}

func (sh *Shell) dispatch(line string) (string, bool) {
	args := tokenize(line)
	if len(args) == 0 {
		return "", false
	}
	cmd := args[0]
	rest := args[1:]

	// A pipeline's first command is what produces the output we fake.
	if i := indexOf(args, "|"); i > 0 {
		cmd, rest = args[0], args[1:i]
	}

	switch cmd {
	case "exit", "logout", "quit":
		return "logout\n", true
	case "pwd":
		return sh.cwd + "\n", false
	case "cd":
		return sh.cd(rest), false
	case "ls", "dir", "ll":
		return sh.ls(cmd, rest), false
	case "cat", "less", "more", "head", "tail", "view":
		return sh.cat(rest), false
	case "whoami":
		return sh.user + "\n", false
	case "id":
		return sh.id(), false
	case "hostname":
		return sh.p.Hostname + "\n", false
	case "uname":
		return sh.uname(rest), false
	case "uptime":
		return sh.p.Uptime(time.Now()) + "\n", false
	case "ps":
		return sh.ps(), false
	case "df":
		return sh.df(), false
	case "free":
		return sh.free(), false
	case "ip", "ifconfig":
		return sh.ipAddr(), false
	case "netstat", "ss":
		return sh.netstat(), false
	case "arp":
		return sh.arp(), false
	case "w", "who", "users":
		return sh.who(), false
	case "last", "lastlog", "lastb":
		if sh.p.Life != nil {
			return sh.p.Life.Last(time.Now(), 40), false
		}
		return "\nwtmp begins " + sh.p.BootTime.Format("Mon Jan  2 15:04:05 2006") + "\n", false
	case "env", "printenv", "set":
		return sh.printEnv(), false
	case "echo":
		return sh.echo(rest), false
	case "history":
		return sh.historyOut(), false
	case "date":
		return time.Now().Format("Mon Jan  2 15:04:05 MST 2006") + "\n", false
	case "wget", "curl", "fetch", "tftp":
		return sh.download(cmd, line), false
	case "ssh", "scp", "sftp", "rsync":
		return sh.remote(cmd, line), false
	case "nc", "ncat", "netcat", "telnet":
		return sh.remote(cmd, line), false
	case "mysql", "psql", "redis-cli", "mongo":
		return fmt.Sprintf("%s: could not connect to server: Connection refused\n", cmd), false
	case "sudo":
		return sh.sudo(rest), false
	case "su":
		return sh.su(rest), false
	case "apt", "apt-get", "yum", "dnf", "apk":
		return sh.pkg(cmd, rest), false
	case "systemctl", "service":
		return sh.systemctl(rest), false
	case "crontab":
		return sh.crontab(rest), false
	case "rm", "shred", "unlink":
		return sh.rm(rest), false
	case "chmod", "chown", "chattr":
		return "", false
	case "touch":
		return sh.touch(rest), false
	case "mkdir":
		return sh.mkdir(rest), false
	case "cp", "mv", "ln":
		return "", false
	case "which", "whereis", "type", "command":
		return sh.which(rest), false
	case "find":
		return sh.find(rest), false
	case "grep", "egrep", "awk", "sed", "sort", "wc", "cut", "tr":
		return "", false
	case "clear", "reset":
		return "\x1b[H\x1b[2J", false
	case "python", "python3", "perl", "ruby", "php", "bash", "sh":
		return sh.interpreter(cmd, line), false
	case "nmap", "masscan", "nikto", "hydra", "sqlmap":
		return fmt.Sprintf("%s: command not found\n", cmd), false
	case "docker", "kubectl", "podman":
		return fmt.Sprintf("%s: command not found\n", cmd), false
	case "lsblk":
		return sh.lsblk(), false
	case "mount":
		return sh.mount(), false
	case "fdisk":
		return sh.fdisk(rest), false
	case "dmesg":
		return sh.dmesg(), false
	case "lscpu":
		return sh.lscpu(), false
	case "cd..":
		return sh.cd([]string{".."}), false
	default:
		return fmt.Sprintf("-bash: %s: command not found\n", cmd), false
	}
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// tokenize splits a command line, honouring simple quoting.
func tokenize(line string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote rune
	)
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func (sh *Shell) cd(args []string) string {
	target := sh.env["HOME"]
	if len(args) > 0 {
		target = args[0]
	}
	if target == "-" {
		target = sh.env["OLDPWD"]
		if target == "" {
			return "-bash: cd: OLDPWD not set\n"
		}
	}
	abs := Resolve(sh.cwd, target)
	if ov, ok := sh.written[abs]; ok {
		if !ov.dir {
			return fmt.Sprintf("-bash: cd: %s: Not a directory\n", target)
		}
	} else {
		n, ok := sh.p.FS.Lookup(abs)
		if !ok {
			return fmt.Sprintf("-bash: cd: %s: No such file or directory\n", target)
		}
		if !n.Dir {
			return fmt.Sprintf("-bash: cd: %s: Not a directory\n", target)
		}
	}
	sh.env["OLDPWD"] = sh.cwd
	sh.cwd = abs
	sh.env["PWD"] = abs
	return ""
}

func (sh *Shell) ls(cmd string, args []string) string {
	long := cmd == "ll"
	all := false
	var target string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "l") {
				long = true
			}
			if strings.Contains(a, "a") {
				all = true
			}
			continue
		}
		target = a
	}
	abs := sh.cwd
	if target != "" {
		abs = Resolve(sh.cwd, target)
	}
	if ov, ok := sh.written[abs]; ok && !ov.dir {
		vn := ov.vnode(path.Base(abs))
		if long {
			return vn.LongFormat() + "\n"
		}
		return vn.Name + "\n"
	}
	n, baseOK := sh.p.FS.Lookup(abs)
	_, ovDir := sh.written[abs]
	if !baseOK && !ovDir {
		return fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", target)
	}
	if baseOK && !n.Dir {
		if long {
			return n.LongFormat() + "\n"
		}
		return n.Name + "\n"
	}
	entries := sh.listDir(abs)

	var b strings.Builder
	if long {
		total := 0
		for _, e := range entries {
			total += int(e.Size)/1024 + 4
		}
		fmt.Fprintf(&b, "total %d\n", total)
	}
	var names []string
	for _, e := range entries {
		if !all && strings.HasPrefix(e.Name, ".") {
			continue
		}
		if long {
			b.WriteString(e.LongFormat() + "\n")
		} else {
			names = append(names, e.Name)
		}
	}
	if !long {
		b.WriteString(strings.Join(names, "  "))
		if len(names) > 0 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (sh *Shell) cat(args []string) string {
	if len(args) == 0 {
		return ""
	}
	var b strings.Builder
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		abs := Resolve(sh.cwd, a)
		// The session overlay shadows the base VFS: an attacker who just wrote a
		// file reads back exactly what they wrote.
		if ov, ok := sh.written[abs]; ok {
			if ov.dir {
				fmt.Fprintf(&b, "cat: %s: Is a directory\n", a)
				continue
			}
			b.WriteString(ov.content)
			continue
		}
		n, ok := sh.p.FS.Lookup(abs)
		if !ok {
			fmt.Fprintf(&b, "cat: %s: No such file or directory\n", a)
			continue
		}
		if n.Dir {
			fmt.Fprintf(&b, "cat: %s: Is a directory\n", a)
			continue
		}
		sh.readEvent(abs, n)
		if live := sh.liveContent(abs); live != "" {
			// auth.log and friends are rendered fresh from the life engine, so
			// the newest line is always minutes old rather than frozen at the
			// moment the decoy booted. The static content stays as a fallback.
			b.WriteString(live)
		} else {
			b.WriteString(n.Content)
		}
	}
	return b.String()
}

// liveContent renders a log file from the synthetic-life engine when the path
// is one whose freshness an attacker checks. An empty return means "serve the
// static content".
func (sh *Shell) liveContent(abs string) string {
	if sh.p.Life == nil {
		return ""
	}
	now := time.Now()
	switch {
	case strings.HasSuffix(abs, "/auth.log"), strings.HasSuffix(abs, "/secure"):
		return sh.p.Life.AuthLog(now, 48)
	}
	return ""
}

// readEvent records a file read, escalating when the file was bait.
func (sh *Shell) readEvent(abs string, n *VNode) {
	sev := event.SeverityLow
	techniques := []event.Technique{{Tactic: "TA0007", Technique: "T1083", Name: "File and Directory Discovery"}}

	switch {
	case n.Honeytoken != "":
		sev = event.SeverityCritical
		techniques = append(techniques, event.Technique{Tactic: "TA0006", Technique: "T1552.001", Name: "Credentials In Files"})
	case strings.HasSuffix(abs, "/shadow"), strings.HasSuffix(abs, "/passwd"):
		sev = event.SeverityHigh
		techniques = append(techniques, event.Technique{Tactic: "TA0006", Technique: "T1003.008", Name: "/etc/passwd and /etc/shadow"})
	case strings.Contains(abs, "id_rsa"), strings.Contains(abs, ".ssh/"):
		sev = event.SeverityHigh
		techniques = append(techniques, event.Technique{Tactic: "TA0006", Technique: "T1552.004", Name: "Private Keys"})
	}

	e := sh.s.Event(event.ClassFileActivity, 2, sev).
		WithMessage("read %s", abs).WithAttack(techniques...)
	e.Set("file_path", abs).Set("file_size", n.Size)
	if n.Honeytoken != "" {
		e.Set("honeytoken", n.Honeytoken)
		e.Message = fmt.Sprintf("honeytoken read: %s (%s)", abs, n.Honeytoken)
	}
	sh.s.Emit(e)
}

func (sh *Shell) id() string {
	uid, gid, name := 0, 0, "root"
	for _, u := range sh.p.Users {
		if u.Name == sh.user {
			uid, gid, name = u.UID, u.GID, u.Name
		}
	}
	if uid == 0 {
		return "uid=0(root) gid=0(root) groups=0(root)\n"
	}
	return fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s),27(sudo)\n", uid, name, gid, name, gid, name)
}

func (sh *Shell) uname(args []string) string {
	flags := strings.Join(args, "")
	if strings.Contains(flags, "a") {
		return fmt.Sprintf("Linux %s %s #1 SMP PREEMPT_DYNAMIC Debian %s %s GNU/Linux\n",
			sh.p.Hostname, sh.p.Kernel, sh.p.Kernel, sh.p.Arch)
	}
	if strings.Contains(flags, "r") {
		return sh.p.Kernel + "\n"
	}
	if strings.Contains(flags, "m") {
		return sh.p.Arch + "\n"
	}
	if strings.Contains(flags, "n") {
		return sh.p.Hostname + "\n"
	}
	return "Linux\n"
}

func (sh *Shell) ps() string {
	rows := []string{
		"root         1  0.0  0.1 168404 11876 ?        Ss   " + sh.p.BootTime.Format("Jan02") + "   0:12 /sbin/init",
		"root       412  0.0  0.0  23408  8092 ?        Ss   " + sh.p.BootTime.Format("Jan02") + "   0:03 /lib/systemd/systemd-journald",
		"root       688  0.0  0.0  15420  6716 ?        Ss   " + sh.p.BootTime.Format("Jan02") + "   0:00 /usr/sbin/cron -f",
		"root       702  0.0  0.0  12180  7104 ?        Ss   " + sh.p.BootTime.Format("Jan02") + "   0:41 sshd: /usr/sbin/sshd -D",
		"root       905  0.0  0.0   8460  2900 ?        Ss   " + sh.p.BootTime.Format("Jan02") + "   0:00 /usr/sbin/rsyslogd -n",
	}
	switch sh.p.Name {
	case "linux/web":
		rows = append(rows,
			"root      1024  0.0  0.0  55240  1712 ?        Ss   "+sh.p.BootTime.Format("Jan02")+"   0:00 nginx: master process /usr/sbin/nginx",
			"www-data  1025  0.0  0.1  55908  6120 ?        S    "+sh.p.BootTime.Format("Jan02")+"   2:14 nginx: worker process")
	case "linux/db":
		rows = append(rows,
			"mysql     1180  1.2  8.4 1893212 682340 ?      Ssl  "+sh.p.BootTime.Format("Jan02")+"  84:11 /usr/sbin/mysqld")
	case "linux/backup":
		rows = append(rows,
			"root      1301  0.0  0.0  12844  3220 ?        Ss   "+sh.p.BootTime.Format("Jan02")+"   0:07 /usr/bin/rsync --daemon")
	}
	rows = append(rows, fmt.Sprintf("%-9s %5d  0.0  0.0   9284  3512 pts/0    R+   %s   0:00 ps aux",
		sh.user, 20000+sh.p.rnd.Intn(9000), time.Now().Format("15:04")))
	return "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" + strings.Join(rows, "\n") + "\n"
}

// df, mount, lsblk and fdisk must tell the same story: an attacker who runs two
// of them and finds sda2 mounted at /home in one and marked [SWAP] in another
// knows the machine is fake. The layout here is the single source of truth --
// sda1 is /, sda2 is swap, sdb1 is /home -- and every disk command renders it.
func (sh *Shell) df() string {
	return "Filesystem     1K-blocks     Used Available Use% Mounted on\n" +
		"udev             4051360        0   4051360   0% /dev\n" +
		"tmpfs             815916     1284    814632   1% /run\n" +
		"/dev/sda1       50395844 18240192  29572000  39% /\n" +
		"tmpfs            4079572        0   4079572   0% /dev/shm\n" +
		"tmpfs               5120        0      5120   0% /run/lock\n" +
		"/dev/sdb1      206291456 71204864 124584448  37% /home\n" +
		"tmpfs             815912        0    815912   0% /run/user/0\n"
}

func (sh *Shell) free() string {
	return "               total        used        free      shared  buff/cache   available\n" +
		"Mem:         8159144     2184320     1204812       31240     4770012     5612884\n" +
		"Swap:        2097148           0     2097148\n"
}

func (sh *Shell) ipAddr() string {
	ip := sh.s.LocalIP()
	if ip == "" || ip == "::" {
		ip = "10.66.0.21"
	}
	return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n" +
		"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
		"    inet 127.0.0.1/8 scope host lo\n" +
		"2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n" +
		fmt.Sprintf("    link/ether %s brd ff:ff:ff:ff:ff:ff\n", sh.mac()) +
		fmt.Sprintf("    inet %s/24 brd 10.66.0.255 scope global ens18\n", ip)
}

func (sh *Shell) mac() string {
	// A believable OUI matters: 52:54:00 screams QEMU to anyone who looks.
	return fmt.Sprintf("00:50:56:%02x:%02x:%02x", sh.p.rnd.Intn(256), sh.p.rnd.Intn(256), sh.p.rnd.Intn(256))
}

func (sh *Shell) netstat() string {
	return "Active Internet connections (servers and established)\n" +
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n" +
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n" +
		fmt.Sprintf("tcp        0     36 %s:22          %s:%d      ESTABLISHED\n",
			sh.s.LocalIP(), sh.s.SrcIP(), sh.s.SrcPort()) +
		"tcp6       0      0 :::22                   :::*                    LISTEN\n"
}

func (sh *Shell) arp() string {
	return "Address                  HWtype  HWaddress           Flags Mask            Iface\n" +
		"10.66.0.1                ether   00:50:56:a1:20:11   C                     ens18\n" +
		"10.66.0.10               ether   00:50:56:a1:44:0c   C                     ens18\n"
}

func (sh *Shell) who() string {
	var b strings.Builder
	// The attacker's own session, first.
	fmt.Fprintf(&b, "%-8s pts/0        %s (%s)\n", sh.user,
		sh.s.Started.Format("2006-01-02 15:04"), sh.s.SrcIP())
	// Then whoever the life engine says is also on. A host where the only
	// logged-in user is the person who just broke in is a host that was
	// abandoned until they arrived -- which is not the busy server the decoy
	// claims to be. These sessions come from the internal subnet, so they are
	// visibly not the attacker.
	if sh.p.Life != nil {
		n := 1
		for _, l := range sh.p.Life.ActiveNow(time.Now()) {
			if l.Service {
				continue // service logins are brief; they rarely show in `w`
			}
			fmt.Fprintf(&b, "%-8s pts/%d        %s (%s)\n", l.User, n,
				l.Start.Format("2006-01-02 15:04"), l.From)
			n++
		}
	}
	return b.String()
}

func (sh *Shell) printEnv() string {
	keys := make([]string, 0, len(sh.env))
	for k := range sh.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, sh.env[k])
	}
	return b.String()
}

func (sh *Shell) echo(args []string) string {
	out := strings.Join(args, " ")
	for k, v := range sh.env {
		out = strings.ReplaceAll(out, "$"+k, v)
	}
	return out + "\n"
}

func (sh *Shell) historyOut() string {
	var b strings.Builder
	for i, h := range sh.history {
		fmt.Fprintf(&b, "%5d  %s\n", i+1, h)
	}
	return b.String()
}

// download answers a fetch attempt without making one. The URL has already been
// recorded as an IOC by Execute.
func (sh *Shell) download(cmd, line string) string {
	urls := urlPattern.FindAllString(line, -1)
	if len(urls) == 0 {
		if cmd == "curl" {
			return "curl: try 'curl --help' or 'curl --manual' for more information\n"
		}
		return cmd + ": missing URL\n"
	}
	// A refusal that looks like a network problem is more believable than a
	// clean success we cannot back up with a real file.
	host := urls[0]
	if i := strings.Index(strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://"), "/"); i > 0 {
		host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")[:i]
	}
	switch cmd {
	case "curl":
		return fmt.Sprintf("curl: (7) Failed to connect to %s port 80 after 2103 ms: Connection refused\n", host)
	case "wget":
		return fmt.Sprintf("--%s--  %s\nResolving %s... failed: Temporary failure in name resolution.\n"+
			"wget: unable to resolve host address '%s'\n",
			time.Now().Format("2006-01-02 15:04:05"), urls[0], host, host)
	default:
		return fmt.Sprintf("%s: connect: Connection refused\n", cmd)
	}
}

// remote answers outbound connection attempts. The decoy must never actually
// reach another host: a honeypot that can be used as a jump box is a liability.
func (sh *Shell) remote(cmd, line string) string {
	e := sh.s.Event(event.ClassDetectionFinding, 1, event.SeverityHigh).
		WithMessage("attempted outbound connection from decoy: %s", line).
		WithAttack(event.Technique{Tactic: "TA0008", Technique: "T1021", Name: "Remote Services"})
	e.Set("command", line).Set("blocked", true).Set("reason", "containment: decoys never initiate outbound connections")
	sh.s.Emit(e)

	switch cmd {
	case "ssh", "scp", "sftp":
		return "ssh: connect to host port 22: Connection timed out\n"
	case "rsync":
		return "rsync: failed to connect: Connection timed out (110)\nrsync error: error in socket IO (code 10)\n"
	default:
		return cmd + ": connect: Connection refused\n"
	}
}

// sudo strips its own options before running what follows. The old version
// passed the whole tail to the shell, so `sudo -l` tried to run "-l" and
// produced "-bash: -l: command not found" -- a giveaway, since real sudo
// parses -l itself. Granting the command keeps the attacker moving, which is
// the point; the interest is in what they reach for once they think they are root.
func (sh *Shell) sudo(args []string) string {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-l" || a == "--list":
			return sh.sudoList()
		case a == "-v", a == "-k", a == "-K", a == "-n":
			return "" // validate/reset timestamp: no output on success
		case a == "-u" || a == "-g" || a == "-p" || a == "-C" || a == "-r" || a == "-t":
			i += 2 // option that takes an argument
		case a == "--":
			i++
			goto run
		case strings.HasPrefix(a, "-"):
			i++ // -H, -E, -s, -i, -b and friends: no argument
		default:
			goto run
		}
	}
	// Only options, no command.
	if len(args) == 0 {
		return "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\n"
	}
	return ""
run:
	cmd := strings.Join(args[i:], " ")
	if cmd == "" {
		return ""
	}
	out, _ := sh.runOne(cmd)
	return out
}

// sudoList renders `sudo -l`. The planted misconfiguration -- an unprivileged
// user who may run anything -- is itself the lure: it is the first privilege
// escalation an attacker checks for, and finding it keeps them engaged.
func (sh *Shell) sudoList() string {
	h := sh.p.Hostname
	return fmt.Sprintf("Matching Defaults entries for %s on %s:\n"+
		"    env_reset, mail_badpass,\n"+
		"    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin, use_pty\n\n"+
		"User %s may run the following commands on %s:\n"+
		"    (ALL : ALL) ALL\n", sh.user, h, sh.user, h)
}

func (sh *Shell) pkg(cmd string, args []string) string {
	if len(args) == 0 {
		return cmd + ": missing operation\n"
	}
	switch args[0] {
	case "update":
		return "Hit:1 http://deb.debian.org/debian bookworm InRelease\n" +
			"Get:2 http://security.debian.org bookworm-security InRelease [48.0 kB]\n" +
			"Fetched 48.0 kB in 1s (41.2 kB/s)\nReading package lists... Done\n"
	case "install":
		return "Reading package lists... Done\nBuilding dependency tree... Done\n" +
			"E: Unable to locate package " + strings.Join(args[1:], " ") + "\n"
	default:
		return ""
	}
}

func (sh *Shell) systemctl(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "status":
		unit := "nginx"
		if len(args) > 1 {
			unit = args[1]
		}
		return fmt.Sprintf("● %s.service - %s\n     Loaded: loaded (/lib/systemd/system/%s.service; enabled)\n"+
			"     Active: active (running) since %s\n   Main PID: 1024 (%s)\n",
			unit, unit, unit, sh.p.BootTime.Format("Mon 2006-01-02 15:04:05 MST"), unit)
	case "stop", "disable", "mask":
		// Stopping services is a ransomware precursor, so it is worth its own
		// high-severity finding rather than a generic command event.
		e := sh.s.Event(event.ClassDetectionFinding, 1, event.SeverityHigh).
			WithMessage("service tampering: systemctl %s", strings.Join(args, " ")).
			WithAttack(event.Technique{Tactic: "TA0040", Technique: "T1489", Name: "Service Stop"})
		e.Set("command", "systemctl "+strings.Join(args, " "))
		sh.s.Emit(e)
		return ""
	default:
		return ""
	}
}

func (sh *Shell) crontab(args []string) string {
	if len(args) > 0 && args[0] == "-l" {
		return "no crontab for " + sh.user + "\n"
	}
	return ""
}

func (sh *Shell) rm(args []string) string {
	target := strings.Join(args, " ")
	if strings.Contains(target, "/var/log") || strings.Contains(target, ".bash_history") ||
		strings.Contains(target, "auth.log") {
		e := sh.s.Event(event.ClassDetectionFinding, 1, event.SeverityHigh).
			WithMessage("log destruction attempt: rm %s", target).
			WithAttack(event.Technique{Tactic: "TA0005", Technique: "T1070.002", Name: "Clear Linux or Mac System Logs"})
		e.Set("target", target)
		sh.s.Emit(e)
	}
	return ""
}

func (sh *Shell) which(args []string) string {
	if len(args) == 0 {
		return ""
	}
	known := map[string]string{
		"bash": "/usr/bin/bash", "sh": "/usr/bin/sh", "python3": "/usr/bin/python3",
		"perl": "/usr/bin/perl", "curl": "/usr/bin/curl", "wget": "/usr/bin/wget",
		"nc": "/usr/bin/nc", "ssh": "/usr/bin/ssh", "gcc": "/usr/bin/gcc",
	}
	var b strings.Builder
	for _, a := range args {
		if p, ok := known[a]; ok {
			b.WriteString(p + "\n")
		}
	}
	return b.String()
}

func (sh *Shell) find(args []string) string {
	root := sh.cwd
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		root = Resolve(sh.cwd, args[0])
	}
	var out []string
	var walk func(p string, n *VNode)
	walk = func(p string, n *VNode) {
		if len(out) > 400 { // bound the answer; a real find would flood too
			return
		}
		out = append(out, p)
		if !n.Dir {
			return
		}
		names := make([]string, 0, len(n.Children))
		for name := range n.Children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child := path.Join(p, name)
			walk(child, n.Children[name])
		}
	}
	n, ok := sh.p.FS.Lookup(root)
	if !ok {
		return fmt.Sprintf("find: '%s': No such file or directory\n", root)
	}
	walk(root, n)
	return strings.Join(out, "\n") + "\n"
}

func (sh *Shell) interpreter(cmd, line string) string {
	if strings.Contains(line, "-c") || strings.Contains(line, "socket") || strings.Contains(line, "pty") {
		e := sh.s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
			WithMessage("interpreter one-liner (possible reverse shell): %s", line).
			WithAttack(
				event.Technique{Tactic: "TA0002", Technique: "T1059.006", Name: "Python"},
				event.Technique{Tactic: "TA0011", Technique: "T1571", Name: "Non-Standard Port"})
		e.Set("command", line)
		sh.s.Emit(e)
		return ""
	}
	return ""
}

func (sh *Shell) lsblk() string {
	return "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n" +
		"sda      8:0    0   50G  0 disk\n├─sda1   8:1    0   49G  0 part /\n└─sda2   8:2    0    1G  0 part [SWAP]\n" +
		"sdb      8:16   0  200G  0 disk\n└─sdb1   8:17   0  200G  0 part /home\n"
}

func (sh *Shell) lscpu() string {
	return "Architecture:            x86_64\n  CPU op-mode(s):        32-bit, 64-bit\n" +
		"CPU(s):                  4\nVendor ID:               GenuineIntel\n" +
		"  Model name:            Intel(R) Xeon(R) Silver 4210R CPU @ 2.40GHz\n" +
		"  Thread(s) per core:    1\n  Core(s) per socket:    4\n"
}

// classify maps a command line to a severity and ATT&CK techniques. It is
// deliberately keyword-driven and conservative: a wrong mapping in an incident
// report costs more than a missing one.
func classify(line string) (event.Severity, []event.Technique) {
	l := strings.ToLower(line)
	add := func(sev event.Severity, ts ...event.Technique) (event.Severity, []event.Technique) {
		return sev, ts
	}
	switch {
	case containsAny(l, "/etc/shadow", "unshadow", "john ", "hashcat"):
		return add(event.SeverityCritical,
			event.Technique{Tactic: "TA0006", Technique: "T1003.008", Name: "/etc/passwd and /etc/shadow"})
	case containsAny(l, "id_rsa", "id_ed25519", ".ssh/", "authorized_keys"):
		return add(event.SeverityHigh,
			event.Technique{Tactic: "TA0006", Technique: "T1552.004", Name: "Private Keys"})
	case containsAny(l, "history -c", "rm -rf /var/log", "shred ", "wevtutil", "truncate -s0"):
		return add(event.SeverityHigh,
			event.Technique{Tactic: "TA0005", Technique: "T1070", Name: "Indicator Removal"})
	case containsAny(l, "crontab", "systemctl enable", "/etc/rc.local", "authorized_keys >>", "useradd", "adduser"):
		return add(event.SeverityHigh,
			event.Technique{Tactic: "TA0003", Technique: "T1053.003", Name: "Cron"})
	case containsAny(l, "wget ", "curl ", "tftp ", "scp "):
		return add(event.SeverityHigh,
			event.Technique{Tactic: "TA0011", Technique: "T1105", Name: "Ingress Tool Transfer"})
	case containsAny(l, "nmap", "masscan", "for i in $(seq", "ping -c 1 10."):
		return add(event.SeverityMedium,
			event.Technique{Tactic: "TA0007", Technique: "T1046", Name: "Network Service Discovery"})
	case containsAny(l, "uname", "whoami", "id", "hostname", "lscpu", "/etc/os-release"):
		return add(event.SeverityLow,
			event.Technique{Tactic: "TA0007", Technique: "T1082", Name: "System Information Discovery"})
	case containsAny(l, "netstat", "ss -", "ifconfig", "ip a", "arp -"):
		return add(event.SeverityLow,
			event.Technique{Tactic: "TA0007", Technique: "T1016", Name: "System Network Configuration Discovery"})
	case containsAny(l, "ps aux", "ps -ef", "top"):
		return add(event.SeverityLow,
			event.Technique{Tactic: "TA0007", Technique: "T1057", Name: "Process Discovery"})
	case containsAny(l, "ls ", "cat ", "find ", "cd "):
		return add(event.SeverityLow,
			event.Technique{Tactic: "TA0007", Technique: "T1083", Name: "File and Directory Discovery"})
	default:
		return add(event.SeverityMedium)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
