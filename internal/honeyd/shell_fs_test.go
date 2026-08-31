package honeyd

import (
	"strings"
	"testing"
)

// The pentest that motivated this file found three things a real host does that
// the decoy did not: it refused garbage passwords and unknown users, it let you
// write a file and read it back, and its disk commands agreed with each other.
// These tests pin all three so they cannot regress.

func TestAcceptsRejectsGarbageAndUnknownUsers(t *testing.T) {
	p, err := BuildPersona("linux/web", "realism-seed")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		user, secret string
		want         bool
		why          string
	}{
		{"root", "toor", true, "planted password for a real user"},
		{"deploy", "deploy123", true, "planted password for a real user"},
		{"deploy", "123456", true, "wildcard secret, real user"},
		{"root", "randwrong-xyz", false, "garbage password must never be accepted"},
		{"deploy2", "123456", false, "wildcard secret must not admit an invented user"},
		{"nosuchuser2", "toor", false, "unknown user, planted-looking password"},
		{"nobody", "123456", false, "nologin system account must not log in"},
	}
	for _, c := range cases {
		if got := p.AcceptsLogin(c.user, c.secret); got != c.want {
			t.Errorf("AcceptsLogin(%q,%q)=%v, want %v (%s)", c.user, c.secret, got, c.want, c.why)
		}
	}
}

func TestShellRedirectionPersistsWithinSession(t *testing.T) {
	p, err := BuildPersona("linux/web", "realism-seed")
	if err != nil {
		t.Fatal(err)
	}
	sh := NewShell(p, newTestSession(p, &collector{}), "root")

	if out, _ := sh.Execute("echo pwned > /tmp/probe"); out != "" {
		t.Fatalf("a redirected echo must not print to the terminal, got %q", out)
	}
	if out, _ := sh.Execute("cat /tmp/probe"); out != "pwned\n" {
		t.Fatalf("written file did not read back: got %q", out)
	}
	// Append must keep the previous content.
	sh.Execute("echo second >> /tmp/probe")
	if out, _ := sh.Execute("cat /tmp/probe"); out != "pwned\nsecond\n" {
		t.Fatalf("append did not preserve content: got %q", out)
	}
	// The written file must show up in ls of its directory.
	if out, _ := sh.Execute("ls /tmp"); !strings.Contains(out, "probe") {
		t.Fatalf("written file not listed by ls: %q", out)
	}
	// Writing under a directory that does not exist fails like bash.
	if out, _ := sh.Execute("echo x > /nonexistent-dir/y"); !strings.Contains(out, "No such file or directory") {
		t.Fatalf("write to a missing directory should fail, got %q", out)
	}
}

func TestShellAppendedAuthorizedKeyIsCriticalPersistence(t *testing.T) {
	p, err := BuildPersona("linux/web", "realism-seed")
	if err != nil {
		t.Fatal(err)
	}
	col := &collector{}
	sh := NewShell(p, newTestSession(p, col), "root")
	sh.Execute("mkdir /root/.ssh")
	sh.Execute("echo ssh-ed25519 AAAA attacker@evil >> /root/.ssh/authorized_keys")
	// The append must be observable back, and it must have raised a critical
	// persistence finding (an SSH key is how an attacker keeps their access).
	if out, _ := sh.Execute("cat /root/.ssh/authorized_keys"); !strings.Contains(out, "attacker@evil") {
		t.Fatalf("authorized_keys did not persist: %q", out)
	}
	var found bool
	for _, e := range col.events {
		w, _ := e.Get("write")
		if e.GetString("file_path") == "/root/.ssh/authorized_keys" && w == true {
			found = true
			if !hasTechnique(e, "T1098.004") {
				t.Errorf("authorized_keys write not mapped to T1098.004: %+v", e.Mirage.Attack)
			}
		}
	}
	if !found {
		t.Fatal("no write event recorded for the authorized_keys append")
	}
}

func TestShellSudoListDoesNotRunDashL(t *testing.T) {
	p, _ := BuildPersona("linux/web", "realism-seed")
	sh := NewShell(p, newTestSession(p, &collector{}), "deploy")
	out, _ := sh.Execute("sudo -l")
	if strings.Contains(out, "command not found") {
		t.Fatalf("sudo -l must not try to run -l as a command: %q", out)
	}
	if !strings.Contains(out, "may run the following commands") {
		t.Fatalf("sudo -l did not render a sudoers listing: %q", out)
	}
}

func TestDiskCommandsAgree(t *testing.T) {
	p, _ := BuildPersona("linux/web", "realism-seed")
	sh := NewShell(p, newTestSession(p, &collector{}), "root")
	mount, _ := sh.Execute("mount")
	df, _ := sh.Execute("df")
	// / is on sda1 everywhere; /home is on sdb1, never sda2 (sda2 is swap).
	if !strings.Contains(mount, "/dev/sda1 on / type ext4") {
		t.Errorf("mount missing sda1 on /: %q", mount)
	}
	if !strings.Contains(mount, "/dev/sdb1 on /home") {
		t.Errorf("mount should put /home on sdb1: %q", mount)
	}
	if strings.Contains(mount, "/dev/sda2 on /home") {
		t.Errorf("mount must not claim sda2 is /home (it is swap): %q", mount)
	}
	if !strings.Contains(df, "/dev/sdb1") || !strings.Contains(df, "/home") {
		t.Errorf("df should show /home on sdb1: %q", df)
	}
	// The old bug: mount fell through to lsblk output.
	if strings.Contains(mount, "MAJ:MIN") {
		t.Errorf("mount must not emit lsblk output: %q", mount)
	}
}
