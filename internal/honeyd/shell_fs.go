package honeyd

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// This file gives the virtual shell a writable session overlay and the disk
// commands that must agree with it. The overlay (Shell.written) lets an
// attacker create files and directories that survive within their session --
// dropping a webshell, appending an SSH key, staging a payload -- without ever
// mutating the shared, read-only persona VFS. A decoy that discards every write
// is one of the easiest honeypots to detect (write a file, read it back, get
// nothing); persisting the write for the session closes that hole. Because a
// shell runs in a single goroutine, the overlay needs no locking.

// maxOverlayBytes bounds what one session can persist, so a loop that writes
// forever cannot exhaust memory. Past it, writes report a full disk.
const maxOverlayBytes = 8 << 20

// redirect is a parsed output redirection (> or >>).
type redirect struct {
	target string
	append bool
}

// parseRedirect pulls an output redirection off a command line and returns the
// command without it. It handles the forms attackers actually type: `> file`,
// `>> file`, `1>`, `&>`, and glued `>file`. stderr redirections (2>, 2>&1) are
// stripped and ignored -- they do not capture stdout.
func parseRedirect(line string) (string, *redirect) {
	toks := tokenize(line)
	var out []string
	var r *redirect
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t == ">" || t == "1>" || t == "&>":
			if i+1 < len(toks) {
				r = &redirect{target: toks[i+1]}
				i++
			}
		case t == ">>" || t == "1>>" || t == "&>>":
			if i+1 < len(toks) {
				r = &redirect{target: toks[i+1], append: true}
				i++
			}
		case t == "2>" || t == "2>>":
			if i+1 < len(toks) {
				i++ // discard the stderr target
			}
		case t == "2>&1" || t == ">&2":
			// nothing to capture
		case strings.HasPrefix(t, ">>") && len(t) > 2:
			r = &redirect{target: t[2:], append: true}
		case strings.HasPrefix(t, ">") && len(t) > 1:
			r = &redirect{target: t[1:]}
		default:
			out = append(out, t)
		}
	}
	return strings.Join(out, " "), r
}

// applyRedirect writes a command's stdout into the overlay instead of the
// terminal, mimicking the shell. It returns whatever should still reach the
// terminal (nothing on success; an error line if the path is unwritable).
func (sh *Shell) applyRedirect(r *redirect, out string) string {
	abs := Resolve(sh.cwd, r.target)
	if sh.isDir(abs) {
		return fmt.Sprintf("-bash: %s: Is a directory\n", r.target)
	}
	if !sh.dirExists(parentDir(abs)) {
		return fmt.Sprintf("-bash: %s: No such file or directory\n", r.target)
	}
	prev := ""
	if r.append {
		prev, _ = sh.readContent(abs)
	}
	if sh.overlayBytes()+len(prev)+len(out) > maxOverlayBytes {
		return fmt.Sprintf("-bash: echo: write error: %s\n", ErrOverlayFull)
	}
	sh.written[abs] = &ovNode{content: prev + out, owner: sh.user, mtime: time.Now()}
	sh.writeEvent(abs, out)
	return ""
}

// ErrOverlayFull is the message a full session overlay reports.
const ErrOverlayFull = "No space left on device"

// writeEvent records a file write, escalating for the paths that matter: an
// authorized_keys append is persistence, a webshell under a web root is a web
// shell, a write to /etc/passwd or sudoers is account manipulation. A plain
// write is still worth a medium finding -- it is an attacker staging something.
func (sh *Shell) writeEvent(abs, content string) {
	sev := event.SeverityMedium
	lower := strings.ToLower(abs)
	techs := []event.Technique{{Tactic: "TA0011", Technique: "T1105", Name: "Ingress Tool Transfer"}}
	switch {
	case strings.Contains(lower, "authorized_keys"):
		sev = event.SeverityCritical
		techs = []event.Technique{{Tactic: "TA0003", Technique: "T1098.004", Name: "SSH Authorized Keys"}}
	case strings.HasSuffix(lower, "/etc/passwd"), strings.HasSuffix(lower, "/etc/shadow"),
		strings.Contains(lower, "/etc/sudoers"):
		sev = event.SeverityCritical
		techs = []event.Technique{{Tactic: "TA0003", Technique: "T1098", Name: "Account Manipulation"}}
	case strings.HasSuffix(lower, ".php"), strings.HasSuffix(lower, ".jsp"),
		strings.HasSuffix(lower, ".jspx"), strings.HasSuffix(lower, ".aspx"),
		strings.HasSuffix(lower, ".asp"), strings.Contains(lower, "/var/www"),
		strings.Contains(lower, "/html/"):
		sev = event.SeverityCritical
		techs = []event.Technique{{Tactic: "TA0003", Technique: "T1505.003", Name: "Web Shell"}}
	case strings.Contains(lower, "cron"), strings.Contains(lower, "/etc/systemd"),
		strings.Contains(lower, "rc.local"), strings.Contains(lower, "/etc/init.d"),
		strings.Contains(lower, "/systemd/system"):
		sev = event.SeverityHigh
		techs = []event.Technique{{Tactic: "TA0003", Technique: "T1053", Name: "Scheduled Task/Job"}}
	}
	e := sh.s.Event(event.ClassFileActivity, 1, sev).
		WithMessage("attacker wrote %s (%d bytes)", abs, len(content)).
		WithAttack(techs...)
	e.Set("file_path", abs).Set("bytes", len(content)).Set("write", true)
	sh.s.Emit(e)
}

// --- overlay helpers ---

func parentDir(abs string) string { return path.Dir(abs) }

// exists reports whether anything is at abs, in the overlay or the base VFS.
func (sh *Shell) exists(abs string) bool {
	if _, ok := sh.written[abs]; ok {
		return true
	}
	_, ok := sh.p.FS.Lookup(abs)
	return ok
}

// isDir reports whether abs is a directory in either layer.
func (sh *Shell) isDir(abs string) bool {
	if ov, ok := sh.written[abs]; ok {
		return ov.dir
	}
	if n, ok := sh.p.FS.Lookup(abs); ok {
		return n.Dir
	}
	return false
}

// dirExists reports whether abs is a directory that a write could target.
func (sh *Shell) dirExists(abs string) bool {
	if abs == "/" || abs == "." {
		return true
	}
	return sh.isDir(abs)
}

// readContent returns the file content at abs from whichever layer holds it.
func (sh *Shell) readContent(abs string) (string, bool) {
	if ov, ok := sh.written[abs]; ok && !ov.dir {
		return ov.content, true
	}
	if n, ok := sh.p.FS.Lookup(abs); ok && !n.Dir {
		return n.Content, true
	}
	return "", false
}

func (sh *Shell) overlayBytes() int {
	total := 0
	for _, ov := range sh.written {
		total += len(ov.content)
	}
	return total
}

// vnode renders an overlay entry as a VNode so ls/find can format it with the
// same code as the base filesystem. The returned node is a throwaway.
func (o *ovNode) vnode(name string) *VNode {
	mode := "-rw-r--r--"
	if o.dir {
		mode = "drwxr-xr-x"
	}
	owner := o.owner
	if owner == "" {
		owner = "root"
	}
	return &VNode{
		Name: name, Dir: o.dir, Mode: mode, Owner: owner, Group: owner,
		Size: int64(len(o.content)), MTime: o.mtime, Content: o.content,
		Children: map[string]*VNode{},
	}
}

// listDir merges the base directory listing with the overlay entries whose
// parent is that directory. Overlay entries shadow base entries of the same
// name, so a file the attacker overwrote lists at its new size.
func (sh *Shell) listDir(abs string) []*VNode {
	byName := map[string]*VNode{}
	if base, ok := sh.p.FS.List(abs); ok {
		for _, e := range base {
			byName[e.Name] = e
		}
	}
	for p, ov := range sh.written {
		if parentDir(p) == abs {
			name := path.Base(p)
			byName[name] = ov.vnode(name)
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*VNode, 0, len(byName))
	for _, n := range names {
		out = append(out, byName[n])
	}
	return out
}

// --- write commands ---

func (sh *Shell) touch(args []string) string {
	var b strings.Builder
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		abs := Resolve(sh.cwd, a)
		if sh.isDir(abs) {
			continue // touch on a directory just updates its mtime
		}
		if !sh.dirExists(parentDir(abs)) {
			fmt.Fprintf(&b, "touch: cannot touch '%s': No such file or directory\n", a)
			continue
		}
		if ov, ok := sh.written[abs]; ok {
			ov.mtime = time.Now()
			continue
		}
		content := ""
		if base, ok := sh.p.FS.Lookup(abs); ok && !base.Dir {
			content = base.Content // touch keeps content, updates time
		}
		if sh.overlayBytes()+len(content) > maxOverlayBytes {
			fmt.Fprintf(&b, "touch: cannot touch '%s': %s\n", a, ErrOverlayFull)
			continue
		}
		sh.written[abs] = &ovNode{content: content, owner: sh.user, mtime: time.Now()}
	}
	return b.String()
}

func (sh *Shell) mkdir(args []string) string {
	parents := false
	var targets []string
	for _, a := range args {
		switch {
		case a == "-p" || a == "--parents":
			parents = true
		case strings.HasPrefix(a, "-"):
			// -m, -v etc.: ignore
		default:
			targets = append(targets, a)
		}
	}
	var b strings.Builder
	for _, t := range targets {
		abs := Resolve(sh.cwd, t)
		if sh.exists(abs) {
			if !parents {
				fmt.Fprintf(&b, "mkdir: cannot create directory '%s': File exists\n", t)
			}
			continue
		}
		if parents {
			sh.mkdirAll(abs)
			continue
		}
		if !sh.dirExists(parentDir(abs)) {
			fmt.Fprintf(&b, "mkdir: cannot create directory '%s': No such file or directory\n", t)
			continue
		}
		sh.written[abs] = &ovNode{dir: true, owner: sh.user, mtime: time.Now()}
	}
	return b.String()
}

// mkdirAll creates abs and any missing ancestors as overlay directories,
// stopping at ones that already exist in either layer.
func (sh *Shell) mkdirAll(abs string) {
	parts := splitPath(abs)
	cur := ""
	for _, part := range parts {
		cur += "/" + part
		if sh.exists(cur) {
			continue
		}
		sh.written[cur] = &ovNode{dir: true, owner: sh.user, mtime: time.Now()}
	}
}

// --- disk and privilege commands that had to become realistic ---

func (sh *Shell) mount() string {
	return "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n" +
		"proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n" +
		"udev on /dev type devtmpfs (rw,nosuid,relatime,size=4051360k,nr_inodes=1012840,mode=755)\n" +
		"devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)\n" +
		"tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=815916k,mode=755)\n" +
		"/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n" +
		"securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)\n" +
		"tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)\n" +
		"tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k,inode64)\n" +
		"cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)\n" +
		"/dev/sda2 on none type swap (rw)\n" +
		"/dev/sdb1 on /home type ext4 (rw,relatime)\n" +
		"tmpfs on /run/user/0 type tmpfs (rw,nosuid,nodev,relatime,size=815912k,nr_inodes=203978,mode=700)\n"
}

func (sh *Shell) fdisk(args []string) string {
	list := false
	for _, a := range args {
		if strings.HasPrefix(a, "-") && strings.Contains(a, "l") {
			list = true
		}
	}
	if !list {
		return "\nWelcome to fdisk (util-linux 2.38.1).\n" +
			"Changes will remain in memory only, until you decide to write them.\n" +
			"Be careful before using the write command.\n\n"
	}
	if sh.user != "root" {
		return "fdisk: cannot open /dev/sda: Permission denied\n"
	}
	return "Disk /dev/sda: 50 GiB, 53687091200 bytes, 104857600 sectors\n" +
		"Disk model: Virtual disk    \n" +
		"Units: sectors of 1 * 512 = 512 bytes\n" +
		"Sector size (logical/physical): 512 bytes / 512 bytes\n" +
		"I/O size (minimum/optimal): 512 bytes / 512 bytes\n" +
		"Disklabel type: dos\n" +
		"Disk identifier: 0x8f3a1c6d\n\n" +
		"Device     Boot     Start       End   Sectors Size Id Type\n" +
		"/dev/sda1  *         2048 102762495 102760448  49G 83 Linux\n" +
		"/dev/sda2       102762496 104857599   2095104   1G 82 Linux swap / Solaris\n\n\n" +
		"Disk /dev/sdb: 200 GiB, 214748364800 bytes, 419430400 sectors\n" +
		"Disk model: Virtual disk    \n" +
		"Units: sectors of 1 * 512 = 512 bytes\n" +
		"Sector size (logical/physical): 512 bytes / 512 bytes\n" +
		"Disklabel type: dos\n" +
		"Disk identifier: 0x2c4e6a8b\n\n" +
		"Device     Boot Start       End   Sectors  Size Id Type\n" +
		"/dev/sdb1        2048 419430399 419428352  200G 83 Linux\n"
}

func (sh *Shell) dmesg() string {
	// Modern Debian sets kernel.dmesg_restrict=1, so a non-root read is denied
	// -- exactly what a real box does, and the honest answer here.
	if sh.user != "root" {
		return "dmesg: read kernel buffer failed: Operation not permitted\n"
	}
	return fmt.Sprintf("[    0.000000] Linux version %s (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14))\n"+
		"[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-%s root=/dev/sda1 ro quiet\n"+
		"[    0.048000] Booting paravirtualized kernel on KVM\n"+
		"[    1.204631] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.\n"+
		"[    2.318004] systemd[1]: Detected virtualization kvm.\n"+
		"[    2.511992] systemd[1]: Detected architecture %s.\n"+
		"[    3.884210] virtio_net virtio0 ens18: renamed from eth0\n",
		sh.p.Kernel, sh.p.Kernel, sh.p.Arch)
}

// su records the escalation attempt and fails. A password prompt on su is read
// from the controlling terminal, which this line-oriented shell does not model;
// the honest, timed failure is closer than the old instant one and the attempt
// itself is the signal worth keeping.
func (sh *Shell) su(args []string) string {
	target := "root"
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		target = a
	}
	e := sh.s.Event(event.ClassAuthentication, 1, event.SeverityMedium).
		WithMessage("su to %s attempted", target).
		WithAttack(event.Technique{Tactic: "TA0004", Technique: "T1548", Name: "Abuse Elevation Control Mechanism"})
	e.Set("target_user", target).Set("method", "su")
	sh.s.Emit(e)
	time.Sleep(2 * time.Second) // real su is deliberately slow to fail
	return "su: Authentication failure\n"
}
