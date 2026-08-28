package life

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// This file turns the login schedule into the text an attacker actually reads:
// the output of `last`, the lines in /var/log/auth.log, and a Windows security
// log. It is all derived from the same schedule, so the story is consistent --
// a login that shows in `last` has a matching "Accepted password" line in
// auth.log at the same second, which is exactly the corroboration an attacker
// uses to decide a host is real.

// Last renders the `last` command's output as of now.
func (e *Engine) Last(now time.Time, maxLines int) string {
	logins := e.Logins(now)
	if maxLines > 0 && len(logins) > maxLines {
		logins = logins[:maxLines]
	}
	var b strings.Builder
	for _, l := range logins {
		when := l.Start.Format("Mon Jan  2 15:04")
		if l.StillLoggedIn() {
			fmt.Fprintf(&b, "%-8s pts/%d       %-15s %s   still logged in\n",
				l.User, e.tty(l), l.From, when)
			continue
		}
		d := l.End.Sub(l.Start)
		fmt.Fprintf(&b, "%-8s pts/%d       %-15s %s - %s  (%02d:%02d)\n",
			l.User, e.tty(l), l.From, when, l.End.Format("15:04"),
			int(d.Hours()), int(d.Minutes())%60)
	}
	// The wtmp begins some time before the window, which is what a real file
	// looks like: it was rotated, not created a month ago exactly.
	fmt.Fprintf(&b, "\nwtmp begins %s\n", now.Add(-Window).Format("Mon Jan  2 15:04:05 2006"))
	return b.String()
}

// tty gives a session a stable pseudo-terminal number so the same login shows
// the same pts across reads.
func (e *Engine) tty(l Login) int {
	return int(e.roll(l.User, l.Start, "tty")) % 8
}

// AuthLog renders /var/log/auth.log up to now, oldest line first as a real log
// file is ordered. Only the recent tail is produced: the file "rotates".
func (e *Engine) AuthLog(now time.Time, tailHours int) string {
	if tailHours <= 0 {
		tailHours = 48
	}
	since := now.Add(-time.Duration(tailHours) * time.Hour)

	type line struct {
		t   time.Time
		msg string
	}
	var lines []line
	add := func(t time.Time, format string, args ...any) {
		if t.Before(since) || t.After(now) {
			return
		}
		lines = append(lines, line{t, fmt.Sprintf(format, args...)})
	}

	for _, l := range e.Logins(now) {
		pid := 1000 + int(e.roll(l.User, l.Start, "pid"))%50000
		if l.Service {
			add(l.Start, "CRON[%d]: pam_unix(cron:session): session opened for user %s(uid=%d) by (uid=0)",
				pid, l.User, 1000+int(e.roll(l.User, time.Time{}, "uid"))%500)
			if !l.StillLoggedIn() {
				add(l.End, "CRON[%d]: pam_unix(cron:session): session closed for user %s", pid, l.User)
			}
			continue
		}
		add(l.Start, "sshd[%d]: Accepted password for %s from %s port %d ssh2",
			pid, l.User, l.From, 40000+int(e.roll(l.User, l.Start, "port"))%20000)
		add(l.Start, "sshd[%d]: pam_unix(sshd:session): session opened for user %s(uid=%d) by (uid=0)",
			pid, l.User, 1000+int(e.roll(l.User, time.Time{}, "uid"))%500)
		if !l.StillLoggedIn() {
			add(l.End, "sshd[%d]: pam_unix(sshd:session): session closed for user %s", pid, l.User)
		}
	}

	// A sprinkling of failed logins from the internet, because a host with a
	// public IP and zero background brute-force noise is a host behind a
	// firewall so tight the attacker would wonder how they reached it.
	for t := since.Truncate(time.Hour); t.Before(now); t = t.Add(time.Hour) {
		if e.roll("noise", t, "fail") > 60 {
			continue
		}
		badUser := []string{"admin", "test", "oracle", "postgres", "user", "git"}[int(e.roll("noise", t, "who"))%6]
		ip := fmt.Sprintf("%d.%d.%d.%d",
			1+int(e.roll("noise", t, "a")),
			int(e.roll("noise", t, "b")),
			int(e.roll("noise", t, "c")),
			1+int(e.roll("noise", t, "d")))
		add(t.Add(time.Duration(e.roll("noise", t, "sec"))%3600*time.Second),
			"sshd[%d]: Failed password for invalid user %s from %s port %d ssh2",
			1000+int(e.roll("noise", t, "pid"))%50000, badUser, ip,
			40000+int(e.roll("noise", t, "port"))%20000)
	}

	sort.Slice(lines, func(i, j int) bool { return lines[i].t.Before(lines[j].t) })
	var b strings.Builder
	host := e.host
	if host == "" {
		host = "server"
	}
	for _, l := range lines {
		fmt.Fprintf(&b, "%s %s %s\n", l.t.Format("Jan  2 15:04:05"), host, l.msg)
	}
	return b.String()
}

// SecurityLog renders a Windows Security event log tail (event 4624, logon) for
// a domain controller decoy, as `wevtutil` or Get-WinEvent would show it.
func (e *Engine) SecurityLog(now time.Time, tailHours int) string {
	if tailHours <= 0 {
		tailHours = 24
	}
	since := now.Add(-time.Duration(tailHours) * time.Hour)
	var b strings.Builder
	for _, l := range e.Logins(now) {
		if l.Start.Before(since) {
			continue
		}
		logonType := 3 // network
		if !l.Service {
			logonType = 2 // interactive
		}
		fmt.Fprintf(&b, "%s  Information  Microsoft-Windows-Security-Auditing  4624  "+
			"An account was successfully logged on. Account: %s\\%s  Logon Type: %d  Source: %s\n",
			l.Start.Format("2006-01-02 15:04:05"), e.netbios(), l.User, logonType, l.From)
	}
	return b.String()
}

func (e *Engine) netbios() string {
	d := e.domain
	if i := strings.IndexByte(d, '.'); i > 0 {
		d = d[:i]
	}
	if d == "" {
		d = "CORP"
	}
	return strings.ToUpper(d)
}
