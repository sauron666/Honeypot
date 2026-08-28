package honeyd

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("http", newHTTP) }

// httpSvc serves a web decoy. It parses requests itself rather than delegating
// to net/http's server so that malformed and hostile requests -- which is most
// of what a honeypot receives -- are recorded instead of rejected with a bare
// 400 by the standard library.
type httpSvc struct {
	p      *Persona
	server string
	site   string // portal | plain
	realm  string
}

func newHTTP(p *Persona, opts map[string]any) (Service, error) {
	h := &httpSvc{p: p, server: p.HTTPServer, site: "portal", realm: p.Hostname}
	if v, ok := opts["server"].(string); ok && v != "" {
		h.server = v
	}
	if v, ok := opts["site"].(string); ok && v != "" {
		h.site = v
	}
	return h, nil
}

func (h *httpSvc) Type() string { return "http" }

func (h *httpSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	br := bufio.NewReader(io.LimitReader(conn, 4*1024*1024))

	for reqNum := 0; reqNum < 64; reqNum++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		req, err := http.ReadRequest(br)
		if err != nil {
			if reqNum == 0 && err != io.EOF {
				// Garbage on port 80 is still evidence: exploit attempts often
				// are not valid HTTP at all.
				s.Emit(s.Event(event.ClassDecoyInteraction, 1, event.SeverityMedium).
					WithMessage("malformed HTTP request").Set("parse_error", err.Error()))
			}
			return nil
		}

		body := h.readBody(req)
		h.record(req, body, s)
		resp, keepAlive := h.respond(req, body, s)

		conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := conn.Write([]byte(resp)); err != nil {
			return err
		}
		if !keepAlive {
			return nil
		}
	}
	return nil
}

// readBody reads a bounded request body; attackers post large payloads.
func (h *httpSvc) readBody(req *http.Request) string {
	if req.Body == nil {
		return ""
	}
	defer req.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(req.Body, 256*1024))
	return string(b)
}

var (
	traversalRe = regexp.MustCompile(`(?i)(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|c:\\windows)`)
	sqliRe      = regexp.MustCompile(`(?i)(union\s+select|' or '1'='1|sleep\(\d+\)|benchmark\(|information_schema|xp_cmdshell)`)
	rceRe       = regexp.MustCompile(`(?i)(;\s*(cat|ls|id|whoami|curl|wget)\b|\$\(.*\)|` + "`" + `.*` + "`" + `|\|\s*(sh|bash)\b)`)
	jndiRe      = regexp.MustCompile(`(?i)\$\{jndi:(ldap|rmi|dns|iiop)://`)
	xssRe       = regexp.MustCompile(`(?i)(<script|javascript:|onerror\s*=)`)
	shellUpload = regexp.MustCompile(`(?i)(<\?php|eval\(\$_(POST|GET|REQUEST)|system\(\$_)`)
	ssrfRe      = regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|localhost:\d+/admin)`)
)

// scannerPaths are URLs with no legitimate reason to be requested. Hitting one
// is not a vulnerability scan finding -- it is a confirmed hostile probe.
var scannerPaths = map[string]string{
	"/.env": "env-file", "/.git/config": "git-config", "/.git/HEAD": "git-config",
	"/wp-login.php": "wordpress", "/wp-admin/": "wordpress", "/xmlrpc.php": "wordpress",
	"/phpmyadmin/": "phpmyadmin", "/pma/": "phpmyadmin", "/adminer.php": "adminer",
	"/actuator/env": "spring-actuator", "/actuator/health": "spring-actuator",
	"/api/v1/namespaces": "kubernetes", "/version": "docker-api", "/containers/json": "docker-api",
	"/config.json": "config-leak", "/backup.sql": "db-dump", "/.aws/credentials": "cloud-credentials",
	"/server-status": "apache-status", "/solr/admin/info/system": "solr",
	"/cgi-bin/luci": "router", "/HNAP1/": "router", "/boaform/admin/formLogin": "router",
	"/_ignition/execute-solution": "laravel-rce", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": "phpunit-rce",
	"/owa/": "exchange", "/autodiscover/autodiscover.json": "exchange-proxylogon",
	"/remote/login": "fortinet-vpn", "/global-protect/login.esp": "palo-alto-vpn",
	"/dana-na/auth/url_default/welcome.cgi": "ivanti-vpn",
}

// record emits the evidence for one request.
func (h *httpSvc) record(req *http.Request, body string, s *Session) {
	full := req.URL.RequestURI()
	headerBlob := ""
	for k, v := range req.Header {
		headerBlob += k + ": " + strings.Join(v, ",") + "\n"
	}
	haystack := full + "\n" + headerBlob + "\n" + body

	sev := event.SeverityLow
	var techniques []event.Technique
	var findings []string

	if kind, ok := scannerPaths[strings.ToLower(req.URL.Path)]; ok {
		sev = event.SeverityHigh
		findings = append(findings, "scanner-path:"+kind)
		techniques = append(techniques, event.Technique{Tactic: "TA0043", Technique: "T1595.003", Name: "Wordlist Scanning"})
	}
	check := func(re *regexp.Regexp, name string, s2 event.Severity, t event.Technique) {
		if re.MatchString(haystack) {
			findings = append(findings, name)
			techniques = append(techniques, t)
			if s2 > sev {
				sev = s2
			}
		}
	}
	check(jndiRe, "log4shell", event.SeverityCritical,
		event.Technique{Tactic: "TA0001", Technique: "T1190", Name: "Exploit Public-Facing Application"})
	check(shellUpload, "webshell-upload", event.SeverityCritical,
		event.Technique{Tactic: "TA0003", Technique: "T1505.003", Name: "Web Shell"})
	check(rceRe, "command-injection", event.SeverityCritical,
		event.Technique{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"})
	check(traversalRe, "path-traversal", event.SeverityHigh,
		event.Technique{Tactic: "TA0007", Technique: "T1083", Name: "File and Directory Discovery"})
	check(sqliRe, "sql-injection", event.SeverityHigh,
		event.Technique{Tactic: "TA0001", Technique: "T1190", Name: "Exploit Public-Facing Application"})
	check(ssrfRe, "ssrf", event.SeverityHigh,
		event.Technique{Tactic: "TA0007", Technique: "T1046", Name: "Network Service Discovery"})
	check(xssRe, "xss", event.SeverityMedium,
		event.Technique{Tactic: "TA0001", Technique: "T1190", Name: "Exploit Public-Facing Application"})

	class := event.ClassHTTPActivity
	if len(findings) > 0 {
		class = event.ClassDetectionFinding
	}
	e := s.Event(class, 1, sev).WithAttack(techniques...)
	if len(findings) > 0 {
		e.WithMessage("%s %s -- %s", req.Method, truncate(full, 200), strings.Join(findings, ", "))
		e.Set("findings", findings)
	} else {
		e.WithMessage("%s %s", req.Method, truncate(full, 200))
	}
	e.Set("http_method", req.Method).
		Set("url_path", req.URL.Path).
		Set("url_query", req.URL.RawQuery).
		Set("user_agent", req.UserAgent()).
		Set("http_version", req.Proto).
		Set("host_header", req.Host).
		Set("headers", truncate(headerBlob, 8192))
	if body != "" {
		e.Set("body", truncate(body, 16384))
	}
	s.Emit(e)
	s.Record("in", []byte(req.Method+" "+full+" "+req.Proto))

	// Basic auth is a credential offer like any other.
	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err == nil {
			user, pass, _ := strings.Cut(string(raw), ":")
			s.AddCredential(Credential{Username: user, Secret: pass, Method: "http-basic", Accepted: false})
		}
	}
	// So is a form login.
	if req.Method == http.MethodPost && body != "" && looksLikeLogin(req.URL.Path, body) {
		if vals, err := url.ParseQuery(body); err == nil {
			user := firstOf(vals, "username", "user", "login", "email", "j_username", "uname")
			pass := firstOf(vals, "password", "pass", "passwd", "j_password", "pwd")
			if user != "" || pass != "" {
				s.AddCredential(Credential{Username: user, Secret: pass, Method: "http-form", Accepted: false})
			}
		}
	}
}

func looksLikeLogin(path, body string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "login") || strings.Contains(p, "signin") || strings.Contains(p, "auth") ||
		strings.Contains(strings.ToLower(body), "password")
}

func firstOf(v url.Values, keys ...string) string {
	for _, k := range keys {
		if s := v.Get(k); s != "" {
			return s
		}
	}
	return ""
}

// respond builds the reply. Believability matters more than correctness here:
// the response has to look like the server the banner claims to be.
func (h *httpSvc) respond(req *http.Request, body string, s *Session) (string, bool) {
	keepAlive := req.ProtoAtLeast(1, 1) && !strings.EqualFold(req.Header.Get("Connection"), "close")

	var status, contentType, payload string
	switch {
	case req.URL.Path == "/" || req.URL.Path == "/index.html":
		status, contentType, payload = "200 OK", "text/html; charset=UTF-8", h.portalHTML("")
	case strings.HasPrefix(req.URL.Path, "/login") || strings.HasPrefix(req.URL.Path, "/signin"):
		if req.Method == http.MethodPost {
			// Rejecting the first attempt is what a real portal does, and it
			// keeps the attacker supplying more credentials.
			status, contentType, payload = "200 OK", "text/html; charset=UTF-8",
				h.portalHTML("Invalid username or password.")
		} else {
			status, contentType, payload = "200 OK", "text/html; charset=UTF-8", h.portalHTML("")
		}
	case req.URL.Path == "/robots.txt":
		status, contentType, payload = "200 OK", "text/plain",
			"User-agent: *\nDisallow: /admin\nDisallow: /backup\nSitemap: /sitemap.xml\n"
	case req.URL.Path == "/favicon.ico":
		status, contentType, payload = "404 Not Found", "text/html", h.notFound(req.URL.Path)
	case req.URL.Path == "/server-status":
		status, contentType, payload = "403 Forbidden", "text/html", h.forbidden()
	case strings.HasPrefix(req.URL.Path, "/trap/") || strings.HasPrefix(req.URL.Path, "/sitemap"):
		status, contentType, payload = "200 OK", "text/html; charset=UTF-8", h.labyrinth(req, s)
	default:
		status, contentType, payload = "404 Not Found", "text/html", h.notFound(req.URL.Path)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(http.TimeFormat))
	fmt.Fprintf(&b, "Server: %s\r\n", h.server)
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(payload))
	if keepAlive {
		b.WriteString("Connection: keep-alive\r\nKeep-Alive: timeout=5, max=100\r\n")
	} else {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(payload)
	return b.String(), keepAlive
}

func (h *httpSvc) portalHTML(errMsg string) string {
	banner := ""
	if errMsg != "" {
		banner = `<p class="err">` + errMsg + `</p>`
	}
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>` + h.realm + ` - Sign in</title>
<style>body{font-family:system-ui,sans-serif;background:#f4f6f8;margin:0}
.box{max-width:340px;margin:8vh auto;background:#fff;padding:28px;border:1px solid #dfe3e8;border-radius:6px}
h1{font-size:18px;margin:0 0 18px}input{width:100%;padding:9px;margin:6px 0 14px;border:1px solid #ccd0d5;border-radius:4px}
button{width:100%;padding:10px;background:#1f6feb;color:#fff;border:0;border-radius:4px;cursor:pointer}
.err{color:#b42318;font-size:13px;margin:0 0 12px}.f{color:#8a94a6;font-size:11px;margin-top:16px;text-align:center}</style>
</head><body><div class="box"><h1>` + h.realm + ` intranet</h1>` + banner + `
<form method="post" action="/login">
<label>Username</label><input name="username" autocomplete="username">
<label>Password</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button></form>
<div class="f">Internal use only. Access is monitored.</div></div></body></html>
`
}

func (h *httpSvc) notFound(path string) string {
	if strings.HasPrefix(h.server, "nginx") {
		return "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n" +
			"<center><h1>404 Not Found</h1></center>\r\n<hr><center>" + h.server + "</center>\r\n</body>\r\n</html>\r\n"
	}
	return "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n" +
		"<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n" +
		"<p>The requested URL " + html(path) + " was not found on this server.</p>\n</body></html>\n"
}

func (h *httpSvc) forbidden() string {
	return "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n" +
		"<center><h1>403 Forbidden</h1></center>\r\n<hr><center>" + h.server + "</center>\r\n</body>\r\n</html>\r\n"
}

// html escapes a path before reflecting it, so that our own decoy page is not
// the XSS an attacker was looking for.
// labyrinth generates an infinite web of internally-linked pages. Every page
// looks like a real intranet directory listing with 10-20 plausible links, each
// of which leads to another generated page. A web scanner that follows them
// burns CPU and time crawling forever, and every request is recorded.
//
// The links are deterministic per path (seeded from the path itself), so a
// scanner that revisits a URL sees the same page — it looks cached, not
// generated. The content includes fake employee names, department names and
// file paths that look worth investigating, which keeps a human attacker
// engaged too.
func (h *httpSvc) labyrinth(req *http.Request, s *Session) string {
	s.Emit(s.Event(event.ClassDecoyInteraction, 1, event.SeverityMedium).
		WithMessage("web labyrinth: scanner following generated links at %s", req.URL.Path).
		WithAttack(event.Technique{Tactic: "TA0007", Technique: "T1083", Name: "File and Directory Discovery"}).
		Set("labyrinth_path", req.URL.Path))

	seed := crc32sum(req.URL.Path)
	rng := seed

	depts := []string{"Finance", "HR", "Engineering", "Legal", "Operations", "IT", "Sales", "Security"}
	names := []string{"reports", "backup", "archive", "exports", "shared", "temp", "docs", "internal"}
	exts := []string{".xlsx", ".docx", ".pdf", ".csv", ".zip", ".bak", ".sql", ".conf"}

	var b strings.Builder
	dept := depts[rng%uint32(len(depts))]
	b.WriteString("<html><head><title>Index of " + html(req.URL.Path) + "</title></head>\n")
	b.WriteString("<body><h1>" + dept + " - " + html(req.URL.Path) + "</h1><hr><pre>\n")
	b.WriteString("<a href=\"../\">../</a>\n")

	nLinks := 10 + int(rng>>8)%12
	for i := 0; i < nLinks; i++ {
		rng = rng*1103515245 + 12345
		name := names[rng%uint32(len(names))]
		rng = rng*1103515245 + 12345
		if rng%3 == 0 {
			b.WriteString(fmt.Sprintf("<a href=\"/trap/%s-%d/\">%s-%d/</a>                                     %s\n",
				name, rng%9999, name, rng%9999, time.Now().AddDate(0, 0, -int(rng%365)).Format("02-Jan-2006 15:04")))
		} else {
			ext := exts[rng%uint32(len(exts))]
			size := 1024 + rng%50000000
			b.WriteString(fmt.Sprintf("<a href=\"/trap/%s-%d%s\">%s-%d%s</a>                              %s  %d\n",
				name, rng%9999, ext, name, rng%9999, ext,
				time.Now().AddDate(0, 0, -int(rng%365)).Format("02-Jan-2006 15:04"), size))
		}
	}
	b.WriteString("</pre><hr></body></html>\n")
	return b.String()
}

func crc32sum(s string) uint32 {
	var h uint32 = 0x811c9dc5
	for _, c := range s {
		h ^= uint32(c)
		h *= 0x01000193
	}
	return h
}

func html(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(truncate(s, 256))
}
