package honeyd

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// Persona is the identity a decoy wears: hostname, OS, banners, users, content
// and the language and naming conventions of the organisation it pretends to
// belong to. A decoy is never "a Linux box" -- it is a specific machine with a
// history, because an empty machine with a three-day uptime is the easiest
// honeypot tell there is (docs/03 §2).
type Persona struct {
	Name     string // "linux/web"
	Vertical string // finance, healthcare, manufacturing, generic
	Language string // BCP-47, drives generated content and user names
	Hostname string
	Domain   string

	OSName       string // "Debian GNU/Linux 12 (bookworm)"
	OSPretty     string
	Kernel       string // uname -r
	Arch         string
	SSHBanner    string // must look like a real build of a real OpenSSH
	HTTPServer   string
	FTPBanner    string
	TelnetBanner string
	MOTD         string

	Users []PersonaUser
	FS    *VFS

	// BootTime backs uptime output. Real servers have been up for months.
	BootTime time.Time

	// WeakSecrets are the credentials the decoy accepts. Accepting an attacker
	// is the point: a decoy that never lets anyone in observes nothing.
	WeakSecrets map[string][]string

	// AcceptAfter lets any credential through after this many attempts, so a
	// brute-force run that never guesses our planted password still ends up
	// inside where we can watch it. Zero disables.
	AcceptAfter int

	// Seed is the deployment seed this persona was built from. Content derived
	// from it is stable across restarts and different between installations,
	// so nothing MIRAGE plants can be signatured across customers.
	Seed string

	rnd *rand.Rand
}

// PersonaUser is an account that exists on the decoy.
type PersonaUser struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
	Gecos string
}

// seedFrom derives a deterministic RNG from the deployment seed and persona
// name. Deterministic so a decoy looks the same after a restart; per-deployment
// so no two installations share artifacts that could be signatured.
func seedFrom(deploySeed, personaName string) *rand.Rand {
	sum := sha256.Sum256([]byte(deploySeed + "|" + personaName))
	return rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(sum[:8]))))
}

// PersonaBuilder constructs a persona.
type PersonaBuilder func(deploySeed string) *Persona

var personaRegistry = map[string]PersonaBuilder{}

// RegisterPersona adds a persona builder to the catalogue.
func RegisterPersona(name string, b PersonaBuilder) { personaRegistry[name] = b }

// BuildPersona instantiates a persona by name.
func BuildPersona(name, deploySeed string) (*Persona, error) {
	b, ok := personaRegistry[name]
	if !ok {
		return nil, fmt.Errorf("honeyd: unknown persona %q (have: %s)", name, strings.Join(PersonaNames(), ", "))
	}
	return b(deploySeed), nil
}

// PersonaNames lists the registered personas.
func PersonaNames() []string {
	out := make([]string, 0, len(personaRegistry))
	for n := range personaRegistry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Liveness reports how lived-in a persona looks: the size of its shell
// histories and the number of log lines it carries.
//
// These are the two things anyone checks after landing on a host, and an empty
// answer to either is the clearest sign that nobody has ever worked here.
func (p *Persona) Liveness() (historyBytes, logLines int) {
	if p.FS == nil {
		return 0, 0
	}
	var walk func(path string, n *VNode)
	walk = func(path string, n *VNode) {
		if n.Dir {
			for name, child := range n.Children {
				walk(path+"/"+name, child)
			}
			return
		}
		base := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			base = path[i+1:]
		}
		lower := strings.ToLower(base)
		switch {
		// "history" rather than a suffix: Windows keeps
		// ConsoleHost_history.txt, and a decoy that only looks lived-in on
		// Linux is a decoy that gives itself away on Windows.
		case strings.Contains(lower, "history"):
			historyBytes += len(n.Content)
		case strings.Contains(path, "/var/log/"), strings.Contains(path, "/Logs/"),
			strings.HasSuffix(lower, ".log"), strings.HasSuffix(lower, ".evtx"):
			logLines += strings.Count(n.Content, "\n")
		}
	}
	walk("", p.FS.root)
	return historyBytes, logLines
}

// Uptime renders the persona's uptime the way `uptime` would.
func (p *Persona) Uptime(now time.Time) string {
	d := now.Sub(p.BootTime)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	load := fmt.Sprintf("%.2f, %.2f, %.2f",
		p.rnd.Float64()*0.6, p.rnd.Float64()*0.5, p.rnd.Float64()*0.4)
	return fmt.Sprintf(" %s up %d days, %2d:%02d,  1 user,  load average: %s",
		now.Format("15:04:05"), days, hours, mins, load)
}

// Accepts reports whether the decoy lets this credential in. attempt is 1-based.
func (p *Persona) Accepts(user, secret string, attempt int) bool {
	for _, s := range p.WeakSecrets[user] {
		if s == secret {
			return true
		}
	}
	for _, s := range p.WeakSecrets["*"] {
		if s == secret {
			return true
		}
	}
	return p.AcceptAfter > 0 && attempt >= p.AcceptAfter
}

// aged returns a timestamp a plausible distance in the past, deterministically.
func (p *Persona) aged(maxDaysAgo int) time.Time {
	d := time.Duration(p.rnd.Intn(maxDaysAgo*24*3600)) * time.Second
	return time.Now().Add(-d - 24*time.Hour)
}

// passwdFile renders /etc/passwd for the persona's users plus the usual system
// accounts, so that `cat /etc/passwd` looks like a real machine.
func (p *Persona) passwdFile() string {
	var b strings.Builder
	system := []string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin",
		"sys:x:3:3:sys:/dev:/usr/sbin/nologin",
		"sync:x:4:65534:sync:/bin:/bin/sync",
		"man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
		"sshd:x:104:65534::/run/sshd:/usr/sbin/nologin",
	}
	for _, l := range system {
		b.WriteString(l + "\n")
	}
	for _, u := range p.Users {
		if u.UID == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n", u.Name, u.UID, u.GID, u.Gecos, u.Home, u.Shell))
	}
	return b.String()
}

// shadowFile renders /etc/shadow. The hashes are real hashes of throwaway
// values: an attacker who cracks one learns a password that unlocks nothing,
// and the attempt itself is the signal we wanted.
func (p *Persona) shadowFile() string {
	var b strings.Builder
	b.WriteString("root:$6$rounds=656000$" + p.randSalt(16) + "$" + p.randSalt(86) + ":19700:0:99999:7:::\n")
	b.WriteString("daemon:*:19700:0:99999:7:::\nbin:*:19700:0:99999:7:::\nsys:*:19700:0:99999:7:::\n")
	for _, u := range p.Users {
		if u.UID == 0 {
			continue
		}
		b.WriteString(u.Name + ":$6$rounds=656000$" + p.randSalt(16) + "$" + p.randSalt(86) + ":19824:0:99999:7:::\n")
	}
	return b.String()
}

const b64chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func (p *Persona) randSalt(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = b64chars[p.rnd.Intn(len(b64chars))]
	}
	return string(b)
}

// RandomToken mints a deterministic-looking secret for planted credentials.
func (p *Persona) RandomToken(n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[p.rnd.Intn(len(alpha))]
	}
	return string(b)
}
