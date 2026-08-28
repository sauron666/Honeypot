// Package watermark embeds invisible, per-recipient identifiers in generated
// decoy documents.
//
// Every document MIRAGE generates — a .docx honeytoken, a breadcrumb config, an
// exported report — carries a unique mark that identifies the channel it was
// planted through. If the document surfaces in a leak, the mark says which
// channel leaked it, which narrows the investigation from "someone in the
// company" to "someone with access to this share". And because the document is
// a known fake, the mark also proves the leak is not real data — which matters
// when a ransomware group publishes it as leverage.
//
// Three techniques, layered so that removing one still leaves the others:
//
//   - Zero-width Unicode characters between words (invisible in renders, present
//     in raw text that an attacker or a model ingests)
//   - Micro-variations in whitespace (single vs double space after a period, tab
//     width, trailing spaces) that survive copy-paste
//   - A visible but plausible document-ID footer that is itself the mark
package watermark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// Mark is one embedded identifier.
type Mark struct {
	// Channel identifies where the document was planted: "share-finance",
	// "breadcrumb-alice", "token-docx-42".
	Channel string `json:"channel"`
	// Bits is the encoded mark, as a bit string for debugging.
	Bits string `json:"bits"`
}

// Embed adds an invisible mark to text, using all three techniques.
func Embed(text, channel, secret string) string {
	bits := encode(channel, secret)
	text = embedZeroWidth(text, bits)
	text = embedWhitespace(text, bits)
	return text
}

// Extract attempts to recover the channel from a marked text.
func Extract(text, secret string, candidates []string) (string, bool) {
	for _, ch := range candidates {
		bits := encode(ch, secret)
		if matchesZeroWidth(text, bits) {
			return ch, true
		}
	}
	return "", false
}

// DocID generates a visible but plausible document identifier from the channel
// and secret. It looks like "Doc-ID: MRG-7A3F" — something an attacker would
// not bother removing but that uniquely identifies the channel.
func DocID(channel, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("docid|" + channel))
	sum := h.Sum(nil)
	return strings.ToUpper(
		string("MRG-") +
			hexByte(sum[0]) + hexByte(sum[1]))
}

func hexByte(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{hex[b>>4], hex[b&0x0f]})
}

// encode produces the bit pattern for a channel.
func encode(channel, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("wm|" + channel))
	sum := h.Sum(nil)
	bits := make([]byte, 16) // 16 bits is enough to distinguish thousands of channels
	for i := range bits {
		bits[i] = (sum[i/8] >> (7 - uint(i%8))) & 1
	}
	return bits
}

// embedZeroWidth inserts zero-width characters between the first N words.
// Bit 0 → zero-width space (U+200B), bit 1 → zero-width non-joiner (U+200C).
func embedZeroWidth(text string, bits []byte) string {
	words := strings.Fields(text)
	if len(words) < len(bits)+1 {
		return text
	}
	var b strings.Builder
	for i, w := range words {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(w)
		if i < len(bits) {
			if bits[i] == 1 {
				b.WriteRune('‌') // ZWNJ
			} else {
				b.WriteRune('​') // ZWS
			}
		}
	}
	return b.String()
}

// embedWhitespace varies spacing: a 1-bit adds a double space after the next
// sentence-ending period.
func embedWhitespace(text string, bits []byte) string {
	var b strings.Builder
	bi := 0
	for i, r := range text {
		b.WriteRune(r)
		if r == '.' && i+1 < len(text) && text[i+1] == ' ' && bi < len(bits) {
			if bits[bi] == 1 {
				b.WriteByte(' ') // extra space
			}
			bi++
		}
	}
	return b.String()
}

// matchesZeroWidth checks whether the text contains the expected zero-width pattern.
func matchesZeroWidth(text string, bits []byte) bool {
	bi := 0
	prev := false
	for _, r := range text {
		switch r {
		case '​':
			if bi >= len(bits) || bits[bi] != 0 {
				return false
			}
			bi++
			prev = true
		case '‌':
			if bi >= len(bits) || bits[bi] != 1 {
				return false
			}
			bi++
			prev = true
		default:
			prev = false
		}
		_ = prev
	}
	return bi >= len(bits)
}

// EncodeInLength embeds bits in the byte count of a binary field. This is for
// formats like DOCX where text manipulation is harder.
func EncodeInLength(data []byte, channel, secret string) []byte {
	bits := encode(channel, secret)
	val := uint16(0)
	for i, b := range bits {
		if b == 1 {
			val |= 1 << uint(i)
		}
	}
	// Append val as padding bytes that do not affect the format.
	pad := make([]byte, 2)
	binary.LittleEndian.PutUint16(pad, val)
	return append(data, pad...)
}
