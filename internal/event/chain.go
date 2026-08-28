package event

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// GenesisHash anchors every chain. It is a constant rather than zeroes so that
// an empty chain is distinguishable from an uninitialised one.
const GenesisHash = "mirage-genesis-v1"

// Chain seals events into an append-only hash chain, giving tamper evidence
// without a database: altering or removing any event breaks every hash after
// it. See docs/05-DATA-MODEL.md.
type Chain struct {
	mu   sync.Mutex
	seq  uint64
	last string
}

// NewChain starts a chain from the genesis anchor.
func NewChain() *Chain { return &Chain{last: GenesisHash} }

// ResumeChain continues an existing chain, for a process restart.
func ResumeChain(seq uint64, lastHash string) *Chain {
	if lastHash == "" {
		lastHash = GenesisHash
	}
	return &Chain{seq: seq, last: lastHash}
}

// Head reports the current sequence number and hash.
func (c *Chain) Head() (uint64, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seq, c.last
}

// Seal assigns the next sequence number and hash to e. It mutates e and is safe
// for concurrent use; events are sealed in the order Seal is called.
func (c *Chain) Seal(e *Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seq++
	e.Metadata.Sequence = c.seq
	e.Mirage.Chain = &ChainLink{Seq: c.seq, PrevHash: c.last}

	h, err := hashEvent(e)
	if err != nil {
		c.seq-- // leave the chain untouched on failure
		e.Mirage.Chain = nil
		return err
	}
	e.Mirage.Chain.Hash = h
	c.last = h
	return nil
}

// hashEvent computes sha256(prev_hash || canonical(event with Hash blanked)).
func hashEvent(e *Event) (string, error) {
	if e.Mirage.Chain == nil {
		return "", fmt.Errorf("event %s: no chain link to hash", e.Metadata.UID)
	}
	saved := e.Mirage.Chain.Hash
	e.Mirage.Chain.Hash = ""
	body, err := CanonicalJSON(e)
	e.Mirage.Chain.Hash = saved
	if err != nil {
		return "", err
	}

	sum := sha256.New()
	sum.Write([]byte(e.Mirage.Chain.PrevHash))
	sum.Write(body)
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// VerifyError describes exactly where a chain broke, so an analyst can point at
// the event rather than at "the log".
type VerifyError struct {
	Index    int
	UID      string
	Reason   string
	Expected string
	Actual   string
}

func (v *VerifyError) Error() string {
	return fmt.Sprintf("chain broken at index %d (uid=%s): %s (expected %s, got %s)",
		v.Index, v.UID, v.Reason, short(v.Expected), short(v.Actual))
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "<empty>"
	}
	return h
}

// Verify replays a contiguous run of events and reports the first break. Pass
// GenesisHash as from for a complete chain, or the hash preceding events[0]
// when verifying a slice.
func Verify(events []*Event, from string) error {
	if from == "" {
		from = GenesisHash
	}
	prev := from
	var prevSeq uint64
	for i, e := range events {
		if e.Mirage.Chain == nil {
			return &VerifyError{Index: i, UID: e.Metadata.UID, Reason: "event is not sealed"}
		}
		if e.Mirage.Chain.PrevHash != prev {
			return &VerifyError{
				Index: i, UID: e.Metadata.UID, Reason: "prev_hash does not match predecessor",
				Expected: prev, Actual: e.Mirage.Chain.PrevHash,
			}
		}
		if i > 0 && e.Mirage.Chain.Seq != prevSeq+1 {
			return &VerifyError{
				Index: i, UID: e.Metadata.UID, Reason: "sequence gap",
				Expected: fmt.Sprint(prevSeq + 1), Actual: fmt.Sprint(e.Mirage.Chain.Seq),
			}
		}
		got, err := hashEvent(e)
		if err != nil {
			return &VerifyError{Index: i, UID: e.Metadata.UID, Reason: err.Error()}
		}
		if got != e.Mirage.Chain.Hash {
			return &VerifyError{
				Index: i, UID: e.Metadata.UID, Reason: "content does not match its hash",
				Expected: e.Mirage.Chain.Hash, Actual: got,
			}
		}
		prev = e.Mirage.Chain.Hash
		prevSeq = e.Mirage.Chain.Seq
	}
	return nil
}
