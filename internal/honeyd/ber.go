package honeyd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// This file holds the small amount of BER/DER handling MIRAGE needs. SNMP and
// LDAP both speak it, and both only need a handful of shapes, so a full ASN.1
// implementation would be more surface than value -- and a decoy must be able
// to survive malformed input from a scanner, which a strict parser tends not to.

// berNext reads the next tag-length-value from b, returning the tag, its value
// and whatever follows.
func berNext(b []byte) (tag byte, value, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("ber: truncated")
	}
	tag = b[0]
	length := int(b[1])
	pos := 2
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, errors.New("ber: bad length encoding")
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(b[2+i])
		}
		pos = 2 + n
	}
	if length < 0 || pos+length > len(b) {
		return 0, nil, nil, fmt.Errorf("ber: length %d exceeds the %d bytes available", length, len(b)-pos)
	}
	return tag, b[pos : pos+length], b[pos+length:], nil
}

// berLength encodes a length in the shortest legal form.
func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// berSeq wraps a body in a tag.
func berSeq(tag byte, body []byte) []byte {
	out := append([]byte{tag}, berLength(len(body))...)
	return append(out, body...)
}

// berString encodes an OCTET STRING.
func berString(s string) []byte { return berSeq(0x04, []byte(s)) }

// berEnum encodes an ENUMERATED.
func berEnum(v int) []byte { return berSeq(0x0a, encodeInt(v)) }

// berInteger encodes an INTEGER.
func berInteger(v int) []byte { return berSeq(0x02, encodeInt(v)) }

func encodeInt(v int) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	neg := v < 0
	if neg {
		// Two's complement over the minimum number of bytes.
		for v != -1 || len(out) == 0 || out[0]&0x80 == 0 {
			out = append([]byte{byte(v)}, out...)
			v >>= 8
		}
		return out
	}
	for v > 0 {
		out = append([]byte{byte(v)}, out...)
		v >>= 8
	}
	if out[0]&0x80 != 0 {
		out = append([]byte{0}, out...)
	}
	return out
}

// readBERMessage reads one complete top-level BER element from a stream.
func readBERMessage(r *bufio.Reader, maxSize int) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	header := []byte{tag, first}

	length := int(first)
	if first&0x80 != 0 {
		n := int(first & 0x7f)
		if n == 0 || n > 4 {
			return nil, fmt.Errorf("ber: unsupported length form 0x%02x", first)
		}
		lenBytes := make([]byte, n)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, err
		}
		header = append(header, lenBytes...)
		length = 0
		for _, b := range lenBytes {
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > maxSize {
		return nil, fmt.Errorf("ber: message of %d bytes is implausible", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}
