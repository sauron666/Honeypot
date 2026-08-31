package fusetrap

import "fmt"

// seed populates the trap with a plausible corporate file server: the kind of
// share ransomware operators hunt for and encrypt first. The documents are
// bait, but they read as real, and several are canaries — files that carry no
// legitimate reason to be opened, so the first touch is already a signal.
//
// The layout deliberately mirrors what an attacker expects on "\\fileserver":
// Finance, HR, Backups. A cryptor that walks the tree top-to-bottom hits a
// canary within the first handful of operations.
func (t *Trap) seed() {
	mk := func(p string, canary bool, body []byte) {
		parent, name := t.parentOf(p)
		if parent == nil {
			return
		}
		n := newFile()
		n.data = body
		n.canary = canary
		n.mtime = t.now()
		parent.children[name] = n
	}
	mkdir := func(p string) {
		parent, name := t.parentOf(p)
		if parent == nil {
			return
		}
		if _, ok := parent.children[name]; !ok {
			parent.children[name] = newDir()
		}
	}

	mkdir("/Finance")
	mkdir("/Finance/2025")
	mkdir("/HR")
	mkdir("/Backups")
	mkdir("/Backups/db")

	doc := func(title string) []byte {
		return []byte("CONFIDENTIAL — " + title + "\n\n" +
			"This document is internal to the company and must not be shared.\n" +
			filler(2200))
	}

	mk("/Finance/2025/Q3-forecast.xlsx", false, doc("Q3 revenue forecast"))
	mk("/Finance/2025/payroll-run.csv", false, doc("payroll export"))
	mk("/Finance/wire-transfer-instructions.docx", false, doc("wire instructions"))
	// Canary: nothing legitimate opens a file named to be irresistible bait.
	mk("/Finance/_ACCOUNT_PASSWORDS.xlsx", true, doc("account passwords"))

	mk("/HR/salaries-2025.xlsx", false, doc("salary bands"))
	mk("/HR/org-chart.pdf", false, doc("org chart"))
	mk("/HR/.DS_Store_do_not_touch", true, doc("canary")) // canary

	mk("/Backups/db/dump-2025-08-30.sql", false, doc("database dump"))
	mk("/Backups/veeam-config.xml", false, doc("backup configuration"))
	mk("/Backups/RESTORE_KEYS.txt", true, doc("restore keys")) // canary
}

// filler produces deterministic, low-entropy, text-like padding so the seeded
// files start as plausible documents (not high-entropy noise the detector
// would misread once a cryptor overwrites them).
func filler(n int) string {
	const lorem = "The quarterly figures were reviewed by the finance committee and " +
		"approved for internal distribution. Please direct any questions to the " +
		"controller. This copy supersedes all prior drafts. "
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, lorem...)
	}
	return string(out[:n]) + fmt.Sprintf("\n[ref %d]\n", n)
}
