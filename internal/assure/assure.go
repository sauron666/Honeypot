// Package assure runs a synthetic attacker against the deployment and checks
// that the whole chain worked.
//
// A silent honeypot is more dangerous than none: it produces the feeling of
// coverage while a broken listener, a full disk or an unreachable SIEM quietly
// swallows everything. Nobody notices, because the expected output of a
// honeypot is silence.
//
// So the platform attacks itself on a schedule, in ways that are recognisable
// but harmless, and then verifies that each step actually happened: the decoy
// answered, the event was recorded, it reached its engagement, and an alert
// went out. Every synthetic action carries a nonce, so its evidence is
// distinguishable from a real intrusion for as long as it exists.
package assure

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/store"
)

// Marker prefixes every synthetic value, so that assurance traffic can never be
// mistaken for a real intrusion in a report, a metric or an alert.
const Marker = "MIRAGE-ASSURE"

// IsSynthetic reports whether an event was produced by the assurance runner.
func IsSynthetic(e *event.Event) bool {
	if strings.Contains(e.Message, Marker) {
		return true
	}
	for _, v := range e.Data {
		if s, ok := v.(string); ok && strings.Contains(s, Marker) {
			return true
		}
	}
	return false
}

// Scenario is one self-test.
type Scenario struct {
	Name    string
	Service string
	// Why explains what breaks silently if this scenario stops working.
	Why string
	// Run performs the action. It must be harmless and must not depend on the
	// decoy's answer beyond completing the exchange.
	Run func(ctx context.Context, addr, nonce string) error
}

// Result is the outcome of one scenario.
type Result struct {
	Scenario string        `json:"scenario"`
	Service  string        `json:"service"`
	Why      string        `json:"why"`
	Skipped  bool          `json:"skipped,omitempty"`
	Reason   string        `json:"reason,omitempty"`
	Acted    bool          `json:"acted"`
	Recorded bool          `json:"recorded"`
	Latency  time.Duration `json:"latency_ns"`
	Events   int           `json:"events"`
	Error    string        `json:"error,omitempty"`
}

// OK reports whether the scenario proved the chain works.
func (r Result) OK() bool { return r.Skipped || (r.Acted && r.Recorded) }

// Report is the outcome of a full run.
type Report struct {
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
	Results   []Result      `json:"results"`
	Passed    int           `json:"passed"`
	Failed    int           `json:"failed"`
	SkippedN  int           `json:"skipped"`
	Healthy   bool          `json:"healthy"`
	Summary   string        `json:"summary"`
}

// Runner drives the self-test.
type Runner struct {
	// Targets maps a service name to the address to attack.
	Targets map[string]string
	Store   store.EventStore
	// Timeout is how long to wait for evidence to appear after acting. The
	// pipeline is asynchronous, so some patience is required -- but not much:
	// evidence that takes a minute to appear is evidence an analyst will not
	// see during an incident.
	Timeout time.Duration
}

// DefaultScenarios covers the protocols whose failure would be least visible.
func DefaultScenarios() []Scenario {
	return []Scenario{
		{
			Name: "http-probe", Service: "http",
			Why: "web decoys are the most-scanned surface; a dead listener here loses the most traffic",
			Run: func(ctx context.Context, addr, nonce string) error {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/.env", nil)
				if err != nil {
					return err
				}
				req.Header.Set("User-Agent", Marker+"/"+nonce)
				resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
				if err != nil {
					return err
				}
				return resp.Body.Close()
			},
		},
		{
			Name: "telnet-login", Service: "telnet",
			Why: "credential capture is the core promise; if it stops working nothing tells you",
			Run: func(ctx context.Context, addr, nonce string) error {
				conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					return err
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				r := bufio.NewReader(conn)
				if err := readUntilPrompt(r, "login:"); err != nil {
					return err
				}
				fmt.Fprintf(conn, "%s-%s\r\n", Marker, nonce)
				if err := readUntilPrompt(r, "Password:"); err != nil {
					return err
				}
				fmt.Fprintf(conn, "%s-%s\r\n", Marker, nonce)
				return nil
			},
		},
		{
			Name: "redis-probe", Service: "redis",
			Why: "the Redis takeover chain is a high-value detection; verify the parser still runs",
			Run: func(ctx context.Context, addr, nonce string) error {
				conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					return err
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				fmt.Fprintf(conn, "SET %s-%s probe\r\nQUIT\r\n", Marker, nonce)
				bufio.NewReader(conn).ReadString('\n')
				return nil
			},
		},
		{
			Name: "ftp-login", Service: "ftp",
			Why: "the file share carries the ransomware engine; a dead FTP listener disables it",
			Run: func(ctx context.Context, addr, nonce string) error {
				conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					return err
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				r := bufio.NewReader(conn)
				r.ReadString('\n') // banner
				fmt.Fprintf(conn, "USER %s-%s\r\n", Marker, nonce)
				r.ReadString('\n')
				fmt.Fprintf(conn, "PASS %s-%s\r\n", Marker, nonce)
				r.ReadString('\n')
				fmt.Fprint(conn, "QUIT\r\n")
				return nil
			},
		},
	}
}

func readUntilPrompt(r *bufio.Reader, want string) error {
	var sb strings.Builder
	buf := make([]byte, 1)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		n, err := r.Read(buf)
		if n > 0 {
			sb.WriteByte(buf[0])
			if strings.Contains(sb.String(), want) {
				return nil
			}
		}
		if err != nil {
			return fmt.Errorf("waiting for %q: %w", want, err)
		}
	}
	return fmt.Errorf("timed out waiting for %q", want)
}

// Run executes every scenario whose service is deployed and verifies the chain.
func (r *Runner) Run(ctx context.Context, scenarios []Scenario) *Report {
	if r.Timeout <= 0 {
		r.Timeout = 15 * time.Second
	}
	rep := &Report{StartedAt: time.Now()}

	for _, sc := range scenarios {
		addr, deployed := r.Targets[sc.Service]
		res := Result{Scenario: sc.Name, Service: sc.Service, Why: sc.Why}

		if !deployed {
			res.Skipped = true
			res.Reason = "no " + sc.Service + " decoy in this deployment"
			rep.Results = append(rep.Results, res)
			continue
		}

		nonce := newNonce()
		start := time.Now()
		if err := sc.Run(ctx, addr, nonce); err != nil {
			res.Error = err.Error()
			rep.Results = append(rep.Results, res)
			continue
		}
		res.Acted = true

		found, n := r.waitForEvidence(ctx, nonce)
		res.Recorded = found
		res.Events = n
		res.Latency = time.Since(start)
		if !found {
			res.Error = fmt.Sprintf(
				"the decoy answered but no evidence carrying the probe reached storage within %s", r.Timeout)
		}
		rep.Results = append(rep.Results, res)
	}

	for _, res := range rep.Results {
		switch {
		case res.Skipped:
			rep.SkippedN++
		case res.OK():
			rep.Passed++
		default:
			rep.Failed++
		}
	}
	rep.Duration = time.Since(rep.StartedAt)
	rep.Healthy = rep.Failed == 0 && rep.Passed > 0
	rep.Summary = summarise(rep)
	return rep
}

func summarise(rep *Report) string {
	switch {
	case rep.Passed == 0 && rep.Failed == 0:
		return "nothing was tested: no scenario matched a deployed decoy"
	case rep.Failed == 0:
		return fmt.Sprintf("the detection chain works end to end: %d scenario(s) verified, %d skipped",
			rep.Passed, rep.SkippedN)
	default:
		var broken []string
		for _, r := range rep.Results {
			if !r.OK() {
				broken = append(broken, r.Scenario)
			}
		}
		sort.Strings(broken)
		return fmt.Sprintf("%d of %d scenario(s) failed (%s): the platform is not detecting what it should",
			rep.Failed, rep.Passed+rep.Failed, strings.Join(broken, ", "))
	}
}

// waitForEvidence polls storage for an event carrying the probe's nonce.
func (r *Runner) waitForEvidence(ctx context.Context, nonce string) (bool, int) {
	deadline := time.Now().Add(r.Timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false, 0
		default:
		}
		events, err := r.Store.Query(ctx, store.Query{Search: nonce, Limit: 50})
		if err == nil && len(events) > 0 {
			return true, len(events)
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false, 0
}

func newNonce() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
