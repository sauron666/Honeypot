// Package store persists evidence. The contract is append-only: an event that
// has been written is never modified or removed by MIRAGE itself, and every
// record carries its hash-chain link so tampering is detectable after the fact.
package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrClosed   = errors.New("store: closed")
)

// Query selects events. Zero-valued fields are ignored, so the empty Query
// returns the most recent events.
type Query struct {
	Since        time.Time
	Until        time.Time
	Plane        event.Plane
	Class        event.Class
	Service      string
	DecoyID      string
	EngagementID string
	SrcIP        string
	MinSeverity  event.Severity
	Search       string // case-insensitive substring over message and Data values
	Limit        int
	Offset       int
	Ascending    bool
}

const defaultLimit = 200

func (q Query) limit() int {
	if q.Limit <= 0 {
		return defaultLimit
	}
	return q.Limit
}

// Matches reports whether e satisfies the query's filters.
func (q Query) Matches(e *event.Event) bool {
	if !q.Since.IsZero() && e.Time < q.Since.UnixMilli() {
		return false
	}
	if !q.Until.IsZero() && e.Time > q.Until.UnixMilli() {
		return false
	}
	if q.Plane != "" && e.Mirage.Plane != q.Plane {
		return false
	}
	if q.Class != 0 && e.ClassUID != q.Class {
		return false
	}
	if q.Service != "" && e.Mirage.Service != q.Service {
		return false
	}
	if q.DecoyID != "" && e.Mirage.DecoyID != q.DecoyID {
		return false
	}
	if q.EngagementID != "" && e.Mirage.EngagementID != q.EngagementID {
		return false
	}
	if q.SrcIP != "" && (e.Src == nil || e.Src.IP != q.SrcIP) {
		return false
	}
	if q.MinSeverity != 0 && e.SeverityID < q.MinSeverity {
		return false
	}
	if q.Search != "" && !matchesSearch(e, q.Search) {
		return false
	}
	return true
}

func matchesSearch(e *event.Event, needle string) bool {
	needle = strings.ToLower(needle)
	if strings.Contains(strings.ToLower(e.Message), needle) {
		return true
	}
	for _, v := range e.Data {
		if s, ok := v.(string); ok && strings.Contains(strings.ToLower(s), needle) {
			return true
		}
	}
	if e.Src != nil && strings.Contains(strings.ToLower(e.Src.IP), needle) {
		return true
	}
	return false
}

// Stats summarises what a store holds.
type Stats struct {
	Events     uint64 `json:"events"`
	InMemory   int    `json:"in_memory"`
	Bytes      int64  `json:"bytes"`
	HeadSeq    uint64 `json:"head_seq"`
	HeadHash   string `json:"head_hash"`
	Oldest     int64  `json:"oldest_ms,omitempty"`
	Newest     int64  `json:"newest_ms,omitempty"`
	Truncated  bool   `json:"memory_truncated"`
	VerifiedAt int64  `json:"verified_at_ms,omitempty"`
}

// EventStore is append-only evidence storage.
type EventStore interface {
	// Append seals the event into the chain and durably records it. It mutates
	// the event to carry its chain link and sequence number.
	Append(ctx context.Context, e *event.Event) error
	Query(ctx context.Context, q Query) ([]*event.Event, error)
	Get(ctx context.Context, uid string) (*event.Event, error)
	// Head returns the chain position, for resuming after a restart.
	Head() (seq uint64, hash string)
	// Verify replays the whole chain from durable storage.
	Verify(ctx context.Context) error
	Stats() Stats
	Close() error
}
