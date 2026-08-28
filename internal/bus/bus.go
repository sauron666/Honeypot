// Package bus is MIRAGE's event transport. The in-memory implementation here is
// the default for single-node deployments (profile P0/P1); a NATS JetStream
// driver plugs in behind the same interface for multi-site store-and-forward.
package bus

import (
	"context"
	"errors"
	"strings"

	"github.com/sauron666/Honeypot/internal/event"
)

// Subject naming convention: mirage.events.<plane>.<class>
const (
	SubjectAll       = "mirage.events.>"
	SubjectPrefix    = "mirage.events."
	SubjectAlerts    = "mirage.alerts"
	SubjectEngagment = "mirage.engagements"
)

// Subject builds the canonical subject for an event.
func Subject(e *event.Event) string {
	return SubjectPrefix + string(e.Mirage.Plane) + "." + e.ClassUID.String()
}

// Handler receives one event. It must not block for long: a slow handler slows
// the decoy that produced the event. Handlers that do real work should hand off
// to their own queue.
type Handler func(ctx context.Context, e *event.Event)

// Subscription is cancelled by calling Unsubscribe.
type Subscription interface {
	Unsubscribe()
	Subject() string
}

// Bus is the transport abstraction.
type Bus interface {
	Publish(ctx context.Context, e *event.Event) error
	PublishSubject(ctx context.Context, subject string, e *event.Event) error
	Subscribe(subject string, h Handler) (Subscription, error)
	Close() error
}

var (
	ErrClosed       = errors.New("bus: closed")
	ErrBadSubject   = errors.New("bus: empty subject")
	ErrNilEvent     = errors.New("bus: nil event")
	ErrInvalidEvent = errors.New("bus: event failed validation")
)

// Match implements NATS-style subject matching: "*" matches exactly one token,
// ">" matches one or more trailing tokens.
func Match(pattern, subject string) bool {
	if pattern == subject {
		return true
	}
	pt := strings.Split(pattern, ".")
	st := strings.Split(subject, ".")
	for i, p := range pt {
		if p == ">" {
			// ">" must consume at least one token.
			return i < len(st)
		}
		if i >= len(st) {
			return false
		}
		if p != "*" && p != st[i] {
			return false
		}
	}
	return len(pt) == len(st)
}
