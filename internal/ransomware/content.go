package ransomware

import (
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Entropy returns Shannon entropy in bits per byte. Encrypted data sits very
// close to 8; English text sits around 4.5; a ZIP or JPEG also sits near 8,
// which is why entropy alone is never enough to call ransomware.
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	total := float64(len(b))
	var h float64
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / total
		h -= p * math.Log2(p)
	}
	return h
}

// SniffKind identifies content by its leading bytes. It is used to notice that
// a file has stopped being what it was, which no editor ever does.
func SniffKind(b []byte) string {
	switch {
	case len(b) >= 4 && string(b[:4]) == "PK\x03\x04":
		return "zip" // also .docx, .xlsx, .pptx, .odt
	case len(b) >= 5 && string(b[:5]) == "%PDF-":
		return "pdf"
	case len(b) >= 8 && string(b[:8]) == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
		return "ole" // legacy .doc, .xls
	case len(b) >= 4 && string(b[:4]) == "\x7fELF":
		return "elf"
	case len(b) >= 2 && string(b[:2]) == "MZ":
		return "pe"
	case len(b) >= 3 && string(b[:3]) == "\xff\xd8\xff":
		return "jpeg"
	case len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n":
		return "png"
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	case len(b) >= 6 && string(b[:6]) == "SQLite":
		return "sqlite"
	case len(b) >= 5 && strings.HasPrefix(string(b[:5]), "<?xml"):
		return "xml"
	case isMostlyText(b):
		return "text"
	default:
		return "unknown"
	}
}

func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) > 1024 {
		b = b[:1024]
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.9
}

// compressedExtensions are formats whose content is legitimately random-looking.
var compressedExtensions = map[string]bool{
	".zip": true, ".gz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true,
	".mp3": true, ".mp4": true, ".mkv": true, ".avi": true, ".pdf": true,
	".docx": true, ".xlsx": true, ".pptx": true,
}

func isCompressedPath(p string) bool {
	return compressedExtensions[strings.ToLower(path.Ext(p))]
}

var (
	emailRe  = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	onionRe  = regexp.MustCompile(`(?i)\b[a-z2-7]{16,56}\.onion\b`)
	btcRe    = regexp.MustCompile(`\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`)
	xmrRe    = regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)
	toxRe    = regexp.MustCompile(`\b[0-9A-Fa-f]{76}\b`)
	urlRe    = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
	ticketRe = regexp.MustCompile(`(?i)\b(?:id|key|token|personal\s+id)\s*[:=]\s*([A-Za-z0-9\-_]{8,64})`)
)

// ExtractContacts pulls the actionable details out of a ransom note.
//
// These are what an incident responder needs first: the onion address and the
// ticket id identify the affiliate and the victim record, and the wallet
// addresses feed straight into blockchain tracing and sanctions checks.
func ExtractContacts(note string) map[string][]string {
	out := map[string][]string{}
	collect := func(key string, matches []string) {
		if len(matches) == 0 {
			return
		}
		seen := map[string]bool{}
		var uniq []string
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				uniq = append(uniq, m)
			}
		}
		sort.Strings(uniq)
		if len(uniq) > 10 {
			uniq = uniq[:10]
		}
		out[key] = uniq
	}
	collect("email", emailRe.FindAllString(note, -1))
	collect("onion", onionRe.FindAllString(note, -1))
	collect("bitcoin", btcRe.FindAllString(note, -1))
	collect("monero", xmrRe.FindAllString(note, -1))
	collect("tox", toxRe.FindAllString(note, -1))
	collect("url", urlRe.FindAllString(note, -1))

	if m := ticketRe.FindAllStringSubmatch(note, -1); len(m) > 0 {
		var ids []string
		for _, g := range m {
			ids = append(ids, g[1])
		}
		collect("victim_id", ids)
	}
	return out
}
