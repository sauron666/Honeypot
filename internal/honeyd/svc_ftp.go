package honeyd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/ransomware"
)

func init() { RegisterService("ftp", newFTP) }

// ftpSvc emulates an FTP server, including passive-mode data transfers so that
// directory listings and downloads actually complete. An attacker who can list
// /srv/backup and pull a file believes the host, and we learn exactly which
// data they were after -- which is the single most useful thing to know about
// an intrusion.
type ftpSvc struct {
	p      *Persona
	banner string
	// tarpitMax bounds how long a single operation may be delayed once the
	// detector is confident. Operators tune it: longer buys more time for
	// responders, shorter keeps the decoy feeling ordinary for longer.
	tarpitMax time.Duration
	// pasvHost is the address advertised in PASV replies. Empty means "the
	// address the control connection arrived on", which is right in most
	// topologies and avoids leaking an internal address.
	pasvHost string
}

func newFTP(p *Persona, opts map[string]any) (Service, error) {
	f := &ftpSvc{p: p, banner: p.FTPBanner, tarpitMax: 8 * time.Second}
	if v, ok := opts["tarpit_max_ms"].(int); ok && v >= 0 {
		f.tarpitMax = time.Duration(v) * time.Millisecond
	}
	if v, ok := opts["banner"].(string); ok && v != "" {
		f.banner = v
	}
	if v, ok := opts["pasv_host"].(string); ok {
		f.pasvHost = v
	}
	return f, nil
}

func (f *ftpSvc) Type() string { return "ftp" }

type ftpState struct {
	user       string
	authed     bool
	cwd        string
	attempt    int
	dataList   net.Listener
	transfers  int
	renameFrom string
	// detect watches this session's file operations. A decoy share has no
	// legitimate writer, so an encryptor stands out immediately.
	detect *ransomware.Detector
}

func (f *ftpSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)
	st := &ftpState{cwd: "/", detect: ransomware.New(ransomware.Options{TarpitMax: f.tarpitMax})}
	defer func() {
		if st.dataList != nil {
			st.dataList.Close()
		}
	}()

	reply := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...) + "\r\n"
		s.Record("out", []byte(msg))
		_, err := conn.Write([]byte(msg))
		return err
	}
	if err := reply("%s", f.banner); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		line, err := r.ReadString('\n')
		if err != nil {
			return nil
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		s.Record("in", []byte(line))

		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(strings.TrimSpace(cmd))
		arg = strings.TrimSpace(arg)

		if st.authed && cmd != "PASS" {
			s.Command("ftp: "+line, ftpSeverity(cmd), ftpTechniques(cmd)...)
		}

		done, err := f.dispatch(ctx, conn, st, cmd, arg, s, reply)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func (f *ftpSvc) dispatch(ctx context.Context, conn net.Conn, st *ftpState, cmd, arg string,
	s *Session, reply func(string, ...any) error) (bool, error) {

	switch cmd {
	case "USER":
		st.user = arg
		return false, reply("331 Please specify the password.")

	case "PASS":
		st.attempt++
		accepted := f.p.AcceptsLogin(st.user, arg)
		s.AddCredential(Credential{Username: st.user, Secret: arg, Method: "ftp", Accepted: accepted})
		if !accepted {
			time.Sleep(1200 * time.Millisecond) // real servers are slow to reject
			return false, reply("530 Login incorrect.")
		}
		st.authed = true
		st.cwd = "/"
		if u := f.homeOf(st.user); u != "" {
			st.cwd = u
		}
		s.Note(event.SeverityHigh, "FTP login accepted for %q", st.user)
		return false, reply("230 Login successful.")

	case "QUIT":
		reply("221 Goodbye.")
		return true, nil

	case "SYST":
		return false, reply("215 UNIX Type: L8")

	case "FEAT":
		return false, reply("211-Features:\r\n PASV\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n UTF8\r\n211 End")

	case "TYPE":
		return false, reply("200 Switching to %s mode.", map[string]string{"I": "Binary", "A": "ASCII"}[arg])

	case "OPTS":
		return false, reply("200 Always in UTF8 mode.")

	case "NOOP":
		return false, reply("200 NOOP ok.")
	}

	if !st.authed {
		return false, reply("530 Please login with USER and PASS.")
	}

	switch cmd {
	case "RNFR":
		st.renameFrom = Resolve(st.cwd, arg)
		if _, ok := f.p.FS.Lookup(st.renameFrom); !ok {
			st.renameFrom = ""
			return false, reply("550 RNFR command failed.")
		}
		return false, reply("350 Ready for RNTO.")

	case "RNTO":
		if st.renameFrom == "" {
			return false, reply("503 RNFR required first.")
		}
		to := Resolve(st.cwd, arg)
		from := st.renameFrom
		st.renameFrom = ""
		f.observe(st, s, ransomware.Op{Kind: ransomware.OpRename, Path: from, NewPath: to})
		e := s.Event(event.ClassFileActivity, 3, event.SeverityMedium).
			WithMessage("FTP rename: %s -> %s", from, to)
		e.Set("file_path", from).Set("new_path", to)
		s.Emit(e)
		return false, reply("250 Rename successful.")

	case "PWD", "XPWD":
		return false, reply("257 \"%s\" is the current directory", st.cwd)

	case "CWD", "XCWD":
		target := Resolve(st.cwd, arg)
		n, ok := f.p.FS.Lookup(target)
		if !ok || !n.Dir {
			return false, reply("550 Failed to change directory.")
		}
		st.cwd = target
		return false, reply("250 Directory successfully changed.")

	case "CDUP":
		st.cwd = Resolve(st.cwd, "..")
		return false, reply("250 Directory successfully changed.")

	case "PASV":
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			return false, reply("425 Cannot open data connection.")
		}
		if st.dataList != nil {
			st.dataList.Close()
		}
		st.dataList = ln
		host := f.pasvHost
		if host == "" {
			host = s.LocalIP()
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ip := strings.ReplaceAll(host, ".", ",")
		if strings.Count(ip, ",") != 3 {
			ip = "127,0,0,1"
		}
		return false, reply("227 Entering Passive Mode (%s,%d,%d).", ip, port>>8, port&0xff)

	case "LIST", "NLST":
		return false, f.sendData(ctx, st, s, reply, func() string {
			return f.listing(Resolve(st.cwd, arg), cmd == "NLST")
		}, "Here comes the directory listing.")

	case "RETR":
		path := Resolve(st.cwd, arg)
		n, ok := f.p.FS.Lookup(path)
		if !ok || n.Dir {
			return false, reply("550 Failed to open file.")
		}
		// A download is exfiltration; if the file was bait, it is the moment
		// the whole deception paid off.
		sev := event.SeverityHigh
		if n.Honeytoken != "" {
			sev = event.SeverityCritical
		}
		e := s.Event(event.ClassFileActivity, 6, sev).
			WithMessage("FTP download: %s", path).
			WithAttack(event.Technique{Tactic: "TA0010", Technique: "T1048.003", Name: "Exfiltration Over Unencrypted Protocol"})
		e.Set("file_path", path).Set("file_size", n.Size)
		if n.Honeytoken != "" {
			e.Set("honeytoken", n.Honeytoken)
		}
		s.Emit(e)
		st.transfers++
		f.observe(st, s, ransomware.Op{Kind: ransomware.OpRead, Path: path, Canary: n.Canary})
		return false, f.sendData(ctx, st, s, reply, func() string { return n.Content },
			fmt.Sprintf("Opening BINARY mode data connection for %s (%d bytes).", arg, n.Size))

	case "STOR", "APPE":
		// Uploads are how a decoy gets a webshell or a ransomware binary. We
		// accept the transfer to capture the payload, and store nothing on the
		// real filesystem.
		return false, f.receiveData(ctx, st, s, reply, Resolve(st.cwd, arg))

	case "DELE", "RMD":
		target := Resolve(st.cwd, arg)
		canary := false
		if n, ok := f.p.FS.Lookup(target); ok {
			canary = n.Canary
		}
		f.observe(st, s, ransomware.Op{Kind: ransomware.OpDelete, Path: target, Canary: canary})
		e := s.Event(event.ClassFileActivity, 4, event.SeverityHigh).
			WithMessage("FTP delete: %s", Resolve(st.cwd, arg)).
			WithAttack(event.Technique{Tactic: "TA0040", Technique: "T1485", Name: "Data Destruction"})
		e.Set("file_path", Resolve(st.cwd, arg))
		s.Emit(e)
		return false, reply("250 Delete operation successful.")

	case "SIZE":
		n, ok := f.p.FS.Lookup(Resolve(st.cwd, arg))
		if !ok || n.Dir {
			return false, reply("550 Could not get file size.")
		}
		return false, reply("213 %d", n.Size)

	case "MDTM":
		n, ok := f.p.FS.Lookup(Resolve(st.cwd, arg))
		if !ok {
			return false, reply("550 Could not get modification time.")
		}
		return false, reply("213 %s", n.MTime.UTC().Format("20060102150405"))

	case "MKD", "XMKD":
		return false, reply("257 \"%s\" created", arg)

	case "SITE":
		return false, reply("500 Unknown SITE command.")

	default:
		return false, reply("500 Unknown command.")
	}
}

// sendData opens the passive data connection and writes the payload.
func (f *ftpSvc) sendData(ctx context.Context, st *ftpState, s *Session,
	reply func(string, ...any) error, payload func() string, msg string) error {

	if st.dataList == nil {
		return reply("425 Use PASV first.")
	}
	if err := reply("150 %s", msg); err != nil {
		return err
	}
	ln := st.dataList
	st.dataList = nil
	defer ln.Close()

	if tl, ok := ln.(*net.TCPListener); ok {
		tl.SetDeadline(time.Now().Add(30 * time.Second))
	}
	dc, err := ln.Accept()
	if err != nil {
		return reply("425 Cannot open data connection.")
	}
	defer dc.Close()
	dc.SetWriteDeadline(time.Now().Add(60 * time.Second))
	dc.Write([]byte(payload()))
	return reply("226 Transfer complete.")
}

// receiveData accepts an upload and records the payload without writing it
// anywhere real.
func (f *ftpSvc) receiveData(ctx context.Context, st *ftpState, s *Session,
	reply func(string, ...any) error, path string) error {

	if st.dataList == nil {
		return reply("425 Use PASV first.")
	}
	if err := reply("150 Ok to send data."); err != nil {
		return err
	}
	ln := st.dataList
	st.dataList = nil
	defer ln.Close()

	if tl, ok := ln.(*net.TCPListener); ok {
		tl.SetDeadline(time.Now().Add(30 * time.Second))
	}
	dc, err := ln.Accept()
	if err != nil {
		return reply("425 Cannot open data connection.")
	}
	defer dc.Close()

	dc.SetReadDeadline(time.Now().Add(120 * time.Second))
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for len(buf) < 4*1024*1024 {
		n, err := dc.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}

	// An upload onto an existing document is not an upload, it is a rewrite --
	// which is what an encryptor does.
	priorKind, canary := "", false
	if n, ok := f.p.FS.Lookup(path); ok {
		priorKind = ransomware.SniffKind([]byte(n.Content))
		canary = n.Canary
	}
	sample := buf
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	f.observe(st, s, ransomware.Op{
		Kind: ransomware.OpWrite, Path: path, Content: sample,
		Size: int64(len(buf)), PriorKind: priorKind, Canary: canary,
	})

	e := s.Event(event.ClassFileActivity, 1, event.SeverityCritical).
		WithMessage("FTP upload captured: %s (%d bytes)", path, len(buf)).
		WithAttack(event.Technique{Tactic: "TA0011", Technique: "T1105", Name: "Ingress Tool Transfer"})
	sum := sha256.Sum256(buf)
	e.Set("file_path", path).
		Set("file_size", len(buf)).
		Set("payload_preview", printableOnly(buf[:min(len(buf), 4096)])).
		Set("payload_kind", sniffPayload(buf)).
		// The hash is what makes a captured upload usable elsewhere: an EDR
		// block list, a YARA rule, a threat intel bundle.
		Set("sha256", hex.EncodeToString(sum[:]))
	s.Emit(e)
	return reply("226 Transfer complete.")
}

// observe feeds one file operation to the ransomware detector, emits whatever
// it finds, and applies the tarpit.
//
// The tarpit is the only defensive action a decoy can safely take: the files
// are worthless, so every second it costs the encryptor is a second the
// responders get for free, and there is nothing real to break.
func (f *ftpSvc) observe(st *ftpState, s *Session, op ransomware.Op) {
	if st.detect == nil {
		return
	}
	for _, finding := range st.detect.Observe(op) {
		sev := event.SeverityHigh
		techniques := []event.Technique{
			{Tactic: "TA0040", Technique: "T1486", Name: "Data Encrypted for Impact"},
		}
		if finding.Kind == ransomware.SignalConfirmed {
			sev = event.SeverityCritical
			techniques = append(techniques,
				event.Technique{Tactic: "TA0040", Technique: "T1490", Name: "Inhibit System Recovery"})
		}
		e := s.Event(event.ClassDetectionFinding, 1, sev).
			WithMessage("ransomware signal (%s): %s", finding.Kind, finding.Message).
			WithAttack(techniques...)
		e.Set("ransomware_signal", string(finding.Kind)).
			Set("ransomware_score", st.detect.Verdict().Score)
		if finding.Path != "" {
			e.Set("file_path", finding.Path)
		}
		for k, v := range finding.Evidence {
			e.Set(k, v)
		}
		s.Emit(e)
	}
	if d := st.detect.Tarpit(); d > 0 {
		time.Sleep(d)
	}
}

func (f *ftpSvc) homeOf(user string) string {
	for _, u := range f.p.Users {
		if u.Name == user {
			return u.Home
		}
	}
	return ""
}

func (f *ftpSvc) listing(path string, namesOnly bool) string {
	entries, ok := f.p.FS.List(path)
	if !ok {
		return ""
	}
	var b strings.Builder
	for _, e := range entries {
		if namesOnly {
			b.WriteString(e.Name + "\r\n")
			continue
		}
		b.WriteString(e.LongFormat() + "\r\n")
	}
	return b.String()
}

// sniffPayload identifies uploaded content by magic bytes and content, so the
// alert says "ELF binary" rather than "4 MB of something".
func sniffPayload(b []byte) string {
	switch {
	case len(b) >= 4 && string(b[:4]) == "\x7fELF":
		return "elf-binary"
	case len(b) >= 2 && string(b[:2]) == "MZ":
		return "pe-binary"
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	case len(b) >= 4 && string(b[:4]) == "PK\x03\x04":
		return "zip"
	case strings.Contains(string(b[:min(len(b), 512)]), "<?php"):
		return "php-webshell"
	case strings.HasPrefix(string(b), "#!"):
		return "script"
	default:
		return "unknown"
	}
}

func ftpSeverity(cmd string) event.Severity {
	switch cmd {
	case "RETR", "STOR", "APPE", "DELE", "RMD":
		return event.SeverityHigh
	case "LIST", "NLST", "CWD":
		return event.SeverityLow
	default:
		return event.SeverityInformational
	}
}

func ftpTechniques(cmd string) []event.Technique {
	switch cmd {
	case "LIST", "NLST", "CWD", "PWD":
		return []event.Technique{{Tactic: "TA0007", Technique: "T1083", Name: "File and Directory Discovery"}}
	case "RETR":
		return []event.Technique{{Tactic: "TA0010", Technique: "T1048.003", Name: "Exfiltration Over Unencrypted Protocol"}}
	case "STOR", "APPE":
		return []event.Technique{{Tactic: "TA0011", Technique: "T1105", Name: "Ingress Tool Transfer"}}
	default:
		return nil
	}
}
