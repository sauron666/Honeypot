package event

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// crockford is Crockford base32: no I, L, O or U, so IDs survive being read
// aloud, copied out of a PDF, or typed into a ticket.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var idMu sync.Mutex

// lastMS and lastRand implement monotonicity within a millisecond, so IDs
// minted in a burst still sort in creation order.
var (
	lastMS   int64
	lastRand [10]byte
)

// NewID returns a 26-character ULID: 48 bits of millisecond timestamp followed
// by 80 bits of entropy, lexicographically sortable by time.
func NewID() string { return newIDAt(time.Now().UnixMilli()) }

func newIDAt(ms int64) string {
	idMu.Lock()
	defer idMu.Unlock()

	if ms == lastMS {
		// Same millisecond: increment the previous entropy instead of drawing
		// fresh bytes, which keeps ordering stable.
		for i := len(lastRand) - 1; i >= 0; i-- {
			lastRand[i]++
			if lastRand[i] != 0 {
				break
			}
		}
	} else {
		lastMS = ms
		if _, err := rand.Read(lastRand[:]); err != nil {
			// crypto/rand does not fail on any platform we support; fall back
			// to the clock rather than panicking inside a hot path.
			binary.BigEndian.PutUint64(lastRand[:8], uint64(time.Now().UnixNano()))
		}
	}

	var raw [16]byte
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	copy(raw[6:], lastRand[:])

	return encodeCrockford(raw)
}

// encodeCrockford renders 128 bits as 26 base32 characters (130 bits of space,
// the top two bits are always zero).
func encodeCrockford(raw [16]byte) string {
	var sb strings.Builder
	sb.Grow(26)
	// Walk the 128 bits from the most significant end in 5-bit groups.
	for i := 0; i < 26; i++ {
		bitPos := i * 5
		var v uint16
		for b := 0; b < 5; b++ {
			pos := bitPos + b - 2 // shift so the last group lands on bit 127
			v <<= 1
			if pos >= 0 && pos < 128 && raw[pos/8]&(1<<(7-uint(pos%8))) != 0 {
				v |= 1
			}
		}
		sb.WriteByte(crockford[v&0x1f])
	}
	return sb.String()
}

// ShortID returns a 12-character identifier for objects that are named by
// humans (decoys, campaigns) where a full ULID is noise.
func ShortID(prefix string) string {
	id := NewID()
	return prefix + "_" + strings.ToLower(id[len(id)-8:])
}
