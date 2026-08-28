package assure

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fingerprint assurance: the platform attacks its own decoys the way a careful
// operator would when deciding whether a host is real.
//
// Every deception product claims its decoys are indistinguishable. None of them
// publishes a number. This does: a Detectability Score per decoy, with the
// specific thing that gives it away and what to do about it. A score that
// cannot go down is a claim; a score that an operator can watch fall release by
// release is a property.
//
// The checks are the ones a human actually runs. Nobody fingerprints a honeypot
// by fuzzing its TCP stack -- they look at whether the machine has a history,
// whether the services on it make sense together, and whether it lies to itself.

// DecoyProfile is everything the fingerprinter knows about one decoy without
// touching the network.
type DecoyProfile struct {
	DecoyID  string
	Persona  string
	Hostname string
	OS       string
	// UptimeDays, HistoryBytes and LogLines describe whether the machine looks
	// lived in. An empty machine with three days of uptime is the single most
	// reliable honeypot tell there is.
	UptimeDays   float64
	HistoryBytes int
	LogLines     int
	// Endpoints maps a service name to an address that can be probed.
	Endpoints map[string]string
}

// FPFinding is one thing that gives a decoy away.
type FPFinding struct {
	Check  string `json:"check"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// Detectability is the verdict for one decoy.
type Detectability struct {
	DecoyID  string      `json:"decoy_id"`
	Persona  string      `json:"persona"`
	Score    int         `json:"score"` // 0 = indistinguishable, 100 = obvious
	Verdict  string      `json:"verdict"`
	Findings []FPFinding `json:"findings"`
}

// FingerprintReport covers a whole deployment.
type FingerprintReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Decoys      []Detectability `json:"decoys"`
	WorstScore  int             `json:"worst_score"`
	Summary     string          `json:"summary"`
}

// knownHoneypotBanners are strings that appear in the default configuration of
// widely deployed honeypots. Any of them is an instant giveaway, because
// detection scripts have grepped for them for years.
var knownHoneypotBanners = map[string]string{
	"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2": "Cowrie's default SSH banner",
	"SSH-2.0-OpenSSH_5.1p1 Debian-5":        "Kippo's default SSH banner",
	"220 Welcome to the ftp service":        "Dionaea's default FTP banner",
	"Nepenthes":                             "the Nepenthes honeypot",
	"Dionaea":                               "the Dionaea honeypot",
	"Cowrie":                                "the Cowrie honeypot",
	"HoneyPy":                               "the HoneyPy honeypot",
	"Kippo":                                 "the Kippo honeypot",
	"OpenCanary":                            "the OpenCanary honeypot",
	"Microsoft-IIS/7.0":                     "a decade-obsolete IIS version most honeypots still advertise",
}

// implausibleTogether lists service pairs that no single real host runs. A
// database, a mail server and a PLC on one address is a honeypot advertising
// itself.
var implausibleTogether = [][2]string{
	{"modbus", "mssql"},
	{"modbus", "mysql"},
	{"modbus", "smtp"},
	{"modbus", "ldap"},
	{"ldap", "redis"},
	{"mssql", "smtp"},
	{"vnc", "modbus"},
}

// Fingerprinter measures how identifiable a deployment's decoys are.
type Fingerprinter struct {
	// Timeout bounds each individual probe.
	Timeout time.Duration
}

// Run scores every decoy.
func (f *Fingerprinter) Run(ctx context.Context, profiles []DecoyProfile) *FingerprintReport {
	if f.Timeout <= 0 {
		f.Timeout = 5 * time.Second
	}
	rep := &FingerprintReport{GeneratedAt: time.Now().UTC()}

	// Decoys are scored in parallel. The timing check deliberately waits for a
	// service to be slow, so doing this serially across a real deployment would
	// take minutes.
	results := make([]Detectability, len(profiles))
	var wg sync.WaitGroup
	for i, p := range profiles {
		wg.Add(1)
		go func(i int, p DecoyProfile) {
			defer wg.Done()
			d := Detectability{DecoyID: p.DecoyID, Persona: p.Persona}
			d.Findings = append(d.Findings, f.checkLivedIn(p)...)
			d.Findings = append(d.Findings, f.checkServiceMix(p)...)
			d.Findings = append(d.Findings, f.checkBanners(ctx, p)...)
			d.Findings = append(d.Findings, f.checkAuthTiming(ctx, p)...)
			d.Findings = append(d.Findings, f.checkOSConsistency(ctx, p)...)

			for _, fnd := range d.Findings {
				d.Score += fnd.Weight
			}
			if d.Score > 100 {
				d.Score = 100
			}
			d.Verdict = verdictFor(d.Score)
			sort.SliceStable(d.Findings, func(a, b int) bool {
				return d.Findings[a].Weight > d.Findings[b].Weight
			})
			results[i] = d
		}(i, p)
	}
	wg.Wait()

	for _, d := range results {
		rep.Decoys = append(rep.Decoys, d)
		if d.Score > rep.WorstScore {
			rep.WorstScore = d.Score
		}
	}

	sort.SliceStable(rep.Decoys, func(i, j int) bool {
		return rep.Decoys[i].Score > rep.Decoys[j].Score
	})
	rep.Summary = fingerprintSummary(rep)
	return rep
}

func verdictFor(score int) string {
	switch {
	case score == 0:
		return "nothing found that would give this decoy away"
	case score < 20:
		return "would survive a careful look"
	case score < 45:
		return "an experienced operator would become suspicious"
	case score < 70:
		return "identifiable as a decoy with modest effort"
	default:
		return "obviously a honeypot"
	}
}

func fingerprintSummary(rep *FingerprintReport) string {
	if len(rep.Decoys) == 0 {
		return "no decoys were profiled"
	}
	worst := rep.Decoys[0]
	if rep.WorstScore == 0 {
		return fmt.Sprintf("%d decoy(s) checked; none of them gives itself away", len(rep.Decoys))
	}
	return fmt.Sprintf("worst detectability %d/100 on %s (%s); %d decoy(s) checked",
		rep.WorstScore, worst.DecoyID, worst.Verdict, len(rep.Decoys))
}

// checkLivedIn looks for the tell that matters most: a machine with no past.
func (f *Fingerprinter) checkLivedIn(p DecoyProfile) []FPFinding {
	var out []FPFinding
	if p.UptimeDays < 30 {
		out = append(out, FPFinding{
			Check: "uptime-too-short", Weight: 20,
			Detail: fmt.Sprintf("the decoy claims %.0f days of uptime; production servers are up for months", p.UptimeDays),
			Fix:    "age the persona's boot time when generating it",
		})
	}
	if p.HistoryBytes < 50 {
		out = append(out, FPFinding{
			Check: "no-shell-history", Weight: 20,
			Detail: "no shell history: the first thing anyone reads after landing, and an empty one means nobody has ever worked here",
			Fix:    "generate a plausible .bash_history for every account with a shell",
		})
	}
	if p.LogLines < 20 {
		out = append(out, FPFinding{
			Check: "empty-logs", Weight: 15,
			Detail: fmt.Sprintf("only %d lines of log history; a real host accumulates thousands", p.LogLines),
			Fix:    "generate access and auth logs covering the claimed uptime",
		})
	}
	return out
}

// checkServiceMix looks for a combination of services no real host would run.
func (f *Fingerprinter) checkServiceMix(p DecoyProfile) []FPFinding {
	var out []FPFinding
	for _, pair := range implausibleTogether {
		_, a := p.Endpoints[pair[0]]
		_, b := p.Endpoints[pair[1]]
		if a && b {
			out = append(out, FPFinding{
				Check: "implausible-service-mix", Weight: 25,
				Detail: fmt.Sprintf("one address serves both %s and %s; no real host does that, "+
					"and a port scan shows it before anyone connects", pair[0], pair[1]),
				Fix: "split these onto separate decoys with separate addresses",
			})
		}
	}
	if len(p.Endpoints) > 8 {
		out = append(out, FPFinding{
			Check: "too-many-services", Weight: 15,
			Detail: fmt.Sprintf("%d services on one address; a scan of a real host rarely finds more than a handful",
				len(p.Endpoints)),
			Fix: "distribute services across decoys, or use projection to give each its own address",
		})
	}
	return out
}

// checkBanners probes what each service announces and compares it against the
// strings honeypot detection scripts have looked for since 2010.
func (f *Fingerprinter) checkBanners(ctx context.Context, p DecoyProfile) []FPFinding {
	var out []FPFinding
	for service, addr := range p.Endpoints {
		banner := f.grabBanner(ctx, addr)
		if banner == "" {
			continue
		}
		for needle, why := range knownHoneypotBanners {
			if strings.Contains(banner, needle) {
				out = append(out, FPFinding{
					Check: "known-honeypot-banner", Weight: 40,
					Detail: fmt.Sprintf("the %s service announces %q, which is %s", service, banner, why),
					Fix:    "set a banner matching a real build of the OS the persona claims",
				})
			}
		}
	}
	return out
}

// grabBanner reads whatever a service says first.
func (f *Fingerprinter) grabBanner(ctx context.Context, addr string) string {
	d := net.Dialer{Timeout: f.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

// checkAuthTiming measures how long a rejected login takes.
//
// Real services are slow to say no: a delay after a bad password is
// deliberate, and its absence is one of the cheapest checks an operator can run.
func (f *Fingerprinter) checkAuthTiming(ctx context.Context, p DecoyProfile) []FPFinding {
	addr, ok := p.Endpoints["telnet"]
	if !ok {
		addr, ok = p.Endpoints["ftp"]
	}
	if !ok {
		return nil
	}

	d := net.Dialer{Timeout: f.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)

	start := time.Now()
	if _, isTelnet := p.Endpoints["telnet"]; isTelnet && addr == p.Endpoints["telnet"] {
		if err := readUntilPrompt(r, "login:"); err != nil {
			return nil
		}
		fmt.Fprint(conn, "definitely-not-a-user\r\n")
		if err := readUntilPrompt(r, "Password:"); err != nil {
			return nil
		}
		fmt.Fprint(conn, "definitely-not-a-password\r\n")
		if err := readUntilPrompt(r, "incorrect"); err != nil {
			return nil
		}
	} else {
		r.ReadString('\n') // banner
		fmt.Fprint(conn, "USER definitely-not-a-user\r\n")
		r.ReadString('\n')
		fmt.Fprint(conn, "PASS definitely-not-a-password\r\n")
		if _, err := r.ReadString('\n'); err != nil {
			return nil
		}
	}
	elapsed := time.Since(start)

	if elapsed < 300*time.Millisecond {
		return []FPFinding{{
			Check: "instant-auth-failure", Weight: 20,
			Detail: fmt.Sprintf("a wrong password was refused in %s; real services delay deliberately, "+
				"and an instant refusal is a cheap, reliable tell", elapsed.Round(time.Millisecond)),
			Fix: "delay rejected authentication by roughly a second, with variation",
		}}
	}
	return nil
}

// checkOSConsistency compares what different services on one decoy claim about
// the machine they run on.
//
// A host whose SSH banner says Debian and whose web server says IIS is not a
// host, and this is the sort of thing an operator notices in seconds.
func (f *Fingerprinter) checkOSConsistency(ctx context.Context, p DecoyProfile) []FPFinding {
	claims := map[string]string{}

	if addr, ok := p.Endpoints["ssh"]; ok {
		if b := f.grabBanner(ctx, addr); b != "" {
			claims["ssh"] = osFamilyOf(b)
		}
	}
	if addr, ok := p.Endpoints["http"]; ok {
		if server := f.httpServerHeader(ctx, addr); server != "" {
			claims["http"] = osFamilyOf(server)
		}
	}
	if p.OS != "" {
		claims["persona"] = osFamilyOf(p.OS)
	}

	seen := map[string][]string{}
	for source, family := range claims {
		if family == "" {
			continue
		}
		seen[family] = append(seen[family], source)
	}
	if len(seen) < 2 {
		return nil
	}
	var parts []string
	for family, sources := range seen {
		sort.Strings(sources)
		parts = append(parts, fmt.Sprintf("%s says %s", strings.Join(sources, "/"), family))
	}
	sort.Strings(parts)
	return []FPFinding{{
		Check: "os-inconsistency", Weight: 30,
		Detail: "the services on this decoy disagree about what it runs: " + strings.Join(parts, "; "),
		Fix:    "derive every banner from the persona rather than configuring them separately",
	}}
}

func (f *Fingerprinter) httpServerHeader(ctx context.Context, addr string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		return ""
	}
	resp, err := (&http.Client{Timeout: f.Timeout}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return resp.Header.Get("Server")
}

// osFamilyOf classifies a banner into the operating system it implies.
func osFamilyOf(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "iis"), strings.Contains(l, "windows"), strings.Contains(l, "microsoft"):
		return "windows"
	case strings.Contains(l, "debian"), strings.Contains(l, "ubuntu"),
		strings.Contains(l, "nginx"), strings.Contains(l, "apache"),
		strings.Contains(l, "centos"), strings.Contains(l, "linux"):
		return "linux"
	default:
		return ""
	}
}
