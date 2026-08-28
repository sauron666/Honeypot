package honeyd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("redis", newRedis) }

// redisSvc emulates an unauthenticated Redis instance -- one of the most
// reliably attacked services on the internet.
//
// The attack worth catching is not the connection, it is the sequence
// CONFIG SET dir / CONFIG SET dbfilename / SET / SAVE, which writes an SSH key
// or a cron entry to disk. Emulating Redis well enough for that sequence to
// complete gets us the attacker's key or payload in full.
type redisSvc struct {
	p       *Persona
	version string
}

func newRedis(p *Persona, opts map[string]any) (Service, error) {
	r := &redisSvc{p: p, version: "6.0.16"}
	if v, ok := opts["version"].(string); ok && v != "" {
		r.version = v
	}
	return r, nil
}

func (r *redisSvc) Type() string { return "redis" }

func (r *redisSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	br := bufio.NewReader(conn)
	store := map[string]string{}
	config := map[string]string{
		"dir": "/var/lib/redis", "dbfilename": "dump.rdb", "maxmemory": "0",
		"requirepass": "", "protected-mode": "no", "bind": "0.0.0.0",
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		args, err := readRESP(br)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(args) == 0 {
			continue
		}
		s.Record("in", []byte(strings.Join(args, " ")))

		cmd := strings.ToUpper(args[0])
		sev, techniques := redisSeverity(cmd, args)
		s.Command("redis: "+strings.Join(args, " "), sev, techniques...)

		reply := r.dispatch(cmd, args, store, config, s)
		s.Record("out", []byte(reply))
		if _, err := conn.Write([]byte(reply)); err != nil {
			return err
		}
		if cmd == "QUIT" {
			return nil
		}
	}
}

func (r *redisSvc) dispatch(cmd string, args []string, store, config map[string]string, s *Session) string {
	switch cmd {
	case "PING":
		if len(args) > 1 {
			return respBulk(args[1])
		}
		return "+PONG\r\n"
	case "QUIT":
		return "+OK\r\n"
	case "AUTH":
		if len(args) > 1 {
			s.AddCredential(Credential{Username: "default", Secret: args[len(args)-1], Method: "redis-auth", Accepted: true})
		}
		return "+OK\r\n"
	case "INFO":
		return respBulk(r.info())
	case "CONFIG":
		return r.configCmd(args, config, s)
	case "SET":
		if len(args) < 3 {
			return "-ERR wrong number of arguments for 'set' command\r\n"
		}
		store[args[1]] = args[2]
		r.inspectPayload(args[1], args[2], s)
		return "+OK\r\n"
	case "GET":
		if len(args) < 2 {
			return "-ERR wrong number of arguments for 'get' command\r\n"
		}
		if v, ok := store[args[1]]; ok {
			return respBulk(v)
		}
		return "$-1\r\n"
	case "DEL":
		n := 0
		for _, k := range args[1:] {
			if _, ok := store[k]; ok {
				delete(store, k)
				n++
			}
		}
		return fmt.Sprintf(":%d\r\n", n)
	case "KEYS":
		keys := make([]string, 0, len(store))
		for k := range store {
			keys = append(keys, k)
		}
		return respArray(keys)
	case "SAVE", "BGSAVE":
		// This is the step that would write the attacker's payload to disk on a
		// real host. We answer success -- so the attacker believes they have
		// persistence and keeps going -- and record it as critical.
		e := s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
			WithMessage("redis persistence write attempt: %s to %s/%s", cmd, config["dir"], config["dbfilename"]).
			WithAttack(
				event.Technique{Tactic: "TA0003", Technique: "T1053.003", Name: "Cron"},
				event.Technique{Tactic: "TA0008", Technique: "T1210", Name: "Exploitation of Remote Services"})
		e.Set("redis_dir", config["dir"]).Set("redis_dbfilename", config["dbfilename"]).Set("keys", len(store))
		for k, v := range store {
			e.Set("payload_"+k, truncate(v, 4096))
		}
		s.Emit(e)
		if cmd == "BGSAVE" {
			return "+Background saving started\r\n"
		}
		return "+OK\r\n"
	case "FLUSHALL", "FLUSHDB":
		for k := range store {
			delete(store, k)
		}
		return "+OK\r\n"
	case "SLAVEOF", "REPLICAOF":
		// Used to load a malicious module from an attacker-controlled master.
		e := s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
			WithMessage("redis replication hijack attempt: %s", strings.Join(args, " ")).
			WithAttack(event.Technique{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"})
		e.Set("command", strings.Join(args, " ")).Set("blocked", true)
		s.Emit(e)
		return "+OK\r\n"
	case "MODULE":
		e := s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
			WithMessage("redis module load attempt: %s", strings.Join(args, " ")).
			WithAttack(event.Technique{Tactic: "TA0002", Technique: "T1129", Name: "Shared Modules"})
		e.Set("command", strings.Join(args, " ")).Set("blocked", true)
		s.Emit(e)
		return "-ERR Error loading the extension. Please check the server logs.\r\n"
	case "COMMAND":
		return "*0\r\n"
	case "SELECT", "CLIENT", "HELLO":
		return "+OK\r\n"
	case "DBSIZE":
		return fmt.Sprintf(":%d\r\n", len(store))
	case "EVAL":
		return "-ERR Error compiling script\r\n"
	default:
		return fmt.Sprintf("-ERR unknown command '%s'\r\n", strings.ToLower(cmd))
	}
}

func (r *redisSvc) configCmd(args []string, config map[string]string, s *Session) string {
	if len(args) < 2 {
		return "-ERR wrong number of arguments for 'config' command\r\n"
	}
	switch strings.ToUpper(args[1]) {
	case "GET":
		if len(args) < 3 {
			return "-ERR wrong number of arguments\r\n"
		}
		want := strings.ToLower(args[2])
		var out []string
		for k, v := range config {
			if want == "*" || k == want {
				out = append(out, k, v)
			}
		}
		return respArray(out)
	case "SET":
		if len(args) < 4 {
			return "-ERR wrong number of arguments\r\n"
		}
		key, val := strings.ToLower(args[2]), args[3]
		config[key] = val
		if key == "dir" || key == "dbfilename" {
			// Redirecting the dump target is the unmistakable first half of the
			// classic Redis RCE chain.
			e := s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
				WithMessage("redis CONFIG SET %s=%s (RCE chain)", key, val).
				WithAttack(event.Technique{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"})
			e.Set("config_key", key).Set("config_value", val)
			s.Emit(e)
		}
		return "+OK\r\n"
	default:
		return "-ERR Unknown CONFIG subcommand\r\n"
	}
}

// inspectPayload classifies what the attacker is trying to write.
func (r *redisSvc) inspectPayload(key, val string, s *Session) {
	var kind string
	switch {
	case strings.Contains(val, "ssh-rsa"), strings.Contains(val, "ssh-ed25519"):
		kind = "ssh-authorized-key"
	case strings.Contains(val, "* * * * *"), strings.Contains(val, "/bin/bash -i"):
		kind = "cron-reverse-shell"
	case strings.Contains(val, "<?php"):
		kind = "php-webshell"
	case strings.Contains(strings.ToLower(val), "curl "), strings.Contains(strings.ToLower(val), "wget "):
		kind = "downloader"
	}
	if kind == "" {
		return
	}
	e := s.Event(event.ClassDetectionFinding, 1, event.SeverityCritical).
		WithMessage("redis payload staged (%s) in key %q", kind, key).
		WithAttack(event.Technique{Tactic: "TA0003", Technique: "T1098.004", Name: "SSH Authorized Keys"})
	e.Set("payload_kind", kind).Set("key", key).Set("payload", truncate(val, 8192))
	s.Emit(e)
}

func (r *redisSvc) info() string {
	return "# Server\r\nredis_version:" + r.version + "\r\nredis_mode:standalone\r\nos:Linux " +
		r.p.Kernel + " x86_64\r\narch_bits:64\r\nprocess_id:1180\r\n" +
		"tcp_port:6379\r\nuptime_in_seconds:8640000\r\nexecutable:/usr/bin/redis-server\r\n" +
		"config_file:/etc/redis/redis.conf\r\n\r\n# Clients\r\nconnected_clients:2\r\n\r\n" +
		"# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\nmaxmemory_policy:noeviction\r\n\r\n" +
		"# Keyspace\r\ndb0:keys=17,expires=3,avg_ttl=0\r\n"
}

func redisSeverity(cmd string, args []string) (event.Severity, []event.Technique) {
	switch cmd {
	case "CONFIG", "SAVE", "BGSAVE", "MODULE", "SLAVEOF", "REPLICAOF", "EVAL":
		return event.SeverityHigh, []event.Technique{
			{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"}}
	case "KEYS", "INFO", "DBSIZE", "SCAN":
		return event.SeverityLow, []event.Technique{
			{Tactic: "TA0007", Technique: "T1082", Name: "System Information Discovery"}}
	case "FLUSHALL", "FLUSHDB":
		return event.SeverityHigh, []event.Technique{
			{Tactic: "TA0040", Technique: "T1485", Name: "Data Destruction"}}
	default:
		return event.SeverityLow, nil
	}
}

// readRESP parses one command, accepting both the RESP array form real clients
// use and the inline form that netcat-driven attackers type by hand.
func readRESP(r *bufio.Reader) ([]string, error) {
	line, err := readLineCRLF(r)
	if err != nil {
		return nil, err
	}
	if line == "" {
		return nil, nil
	}
	if line[0] != '*' {
		// Inline commands, which is what an attacker driving Redis through
		// netcat sends. Real Redis honours quoting and escapes here, and so
		// must we: without it a quoted payload is shredded into fragments and
		// the detection that matters never fires.
		return splitInline(line), nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil || n < 0 || n > 1024 {
		return nil, fmt.Errorf("redis: bad multibulk header %q", line)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := readLineCRLF(r)
		if err != nil {
			return nil, err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, fmt.Errorf("redis: bad bulk header %q", hdr)
		}
		length, err := strconv.Atoi(strings.TrimSpace(hdr[1:]))
		if err != nil || length < -1 || length > 8*1024*1024 {
			return nil, fmt.Errorf("redis: bad bulk length %q", hdr)
		}
		if length == -1 {
			out = append(out, "")
			continue
		}
		buf := make([]byte, length+2) // payload plus CRLF
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf[:length]))
	}
	return out, nil
}

// splitInline tokenises a Redis inline command the way redis-cli does:
// whitespace separated, with single and double quoted arguments and the escape
// sequences Redis supports inside double quotes.
func splitInline(line string) []string {
	var (
		out   []string
		cur   strings.Builder
		inArg bool
		quote byte
	)
	flush := func() {
		if inArg {
			out = append(out, cur.String())
			cur.Reset()
			inArg = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == '"':
			if c == '\\' && i+1 < len(line) {
				i++
				switch line[i] {
				case 'n':
					cur.WriteByte('\n')
				case 'r':
					cur.WriteByte('\r')
				case 't':
					cur.WriteByte('\t')
				case 'b':
					cur.WriteByte('\b')
				case 'a':
					cur.WriteByte(7)
				case 'x':
					if i+2 < len(line) {
						if v, err := strconv.ParseUint(line[i+1:i+3], 16, 8); err == nil {
							cur.WriteByte(byte(v))
							i += 2
							continue
						}
					}
					cur.WriteByte('x')
				default:
					cur.WriteByte(line[i])
				}
				continue
			}
			if c == '"' {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case quote == '\'':
			if c == '\'' {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
			inArg = true
		case c == ' ' || c == '\t':
			flush()
		default:
			inArg = true
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func readLineCRLF(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > 64*1024 {
		return "", fmt.Errorf("redis: line too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func respBulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

func respArray(items []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(items))
	for _, i := range items {
		b.WriteString(respBulk(i))
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
