package honeyd

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// TestSanitizeProducesValidUTF8 pins the fix for the anti-forensics bug a live
// pentest found: a transcript with invalid UTF-8 must come out valid, so it
// survives the JSON encode/decode round-trip the evidence chain relies on, and
// it must preserve the exact byte the attacker sent rather than lose it to �.
func TestSanitizeProducesValidUTF8(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"invalid high bytes", []byte{0x80, 0x81, 0xfe}, `\x80\x81\xfe`},
		{"valid cyrillic passes", []byte("привет"), "привет"},
		{"control chars escaped", []byte{0x01, '\t', '\n'}, `\x01\t\n`},
		{"ascii passes", []byte("ls -la /root"), "ls -la /root"},
		{"lone continuation byte", []byte("ab\xc3z"), `ab\xc3z`}, // truncated 2-byte seq
	}
	for _, c := range cases {
		got := string(sanitize(c.in))
		if !utf8.ValidString(got) {
			t.Errorf("%s: sanitize output is not valid UTF-8: %q", c.name, got)
		}
		if got != c.want {
			t.Errorf("%s: sanitize(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
		// The output must survive a JSON round-trip byte-for-byte (this is what
		// keeps the hash chain stable).
		enc, _ := json.Marshal(got)
		var back string
		json.Unmarshal(enc, &back)
		if back != got {
			t.Errorf("%s: JSON round-trip changed the string: %q -> %q", c.name, got, back)
		}
	}
}
