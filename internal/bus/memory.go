package bus

import (
	"context"
	"log/slog"
	"sync"

	"github.com/sauron666/Honeypot/internal/event"
)

// Memory is an in-process bus. Delivery is asynchronous and per-subscriber
// buffered: one wedged subscriber must never stall a decoy handler, so an
// overflowing subscriber drops events and says so loudly rather than blocking.
type Memory struct {
	mu     sync.RWMutex
	subs   map[int]*memSub
	nextID int
	closed bool

	bufSize int
	log     *slog.Logger

	// dropped counts events shed by full subscriber queues; surfaced through
	// Stats so that a silent loss of evidence is impossible.
	dropped uint64
}

type memSub struct {
	id      int
	subject string
	ch      chan *event.Event
	done    chan struct{}
	bus     *Memory
	once    sync.Once
}

func (s *memSub) Subject() string { return s.subject }

func (s *memSub) Unsubscribe() {
	s.once.Do(func() {
		s.bus.mu.Lock()
		delete(s.bus.subs, s.id)
		s.bus.mu.Unlock()
		close(s.done)
	})
}

// NewMemory creates an in-process bus. bufSize is the per-subscriber queue
// depth; 1024 is a sane default for a single node.
func NewMemory(bufSize int, log *slog.Logger) *Memory {
	if bufSize <= 0 {
		bufSize = 1024
	}
	if log == nil {
		log = slog.Default()
	}
	return &Memory{subs: map[int]*memSub{}, bufSize: bufSize, log: log}
}

// Publish sends the event on its canonical subject.
func (m *Memory) Publish(ctx context.Context, e *event.Event) error {
	if e == nil {
		return ErrNilEvent
	}
	return m.PublishSubject(ctx, Subject(e), e)
}

// PublishSubject sends the event on an explicit subject.
func (m *Memory) PublishSubject(ctx context.Context, subject string, e *event.Event) error {
	if e == nil {
		return ErrNilEvent
	}
	if subject == "" {
		return ErrBadSubject
	}
	if err := e.Validate(); err != nil {
		return ErrInvalidEvent
	}

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrClosed
	}
	targets := make([]*memSub, 0, 4)
	for _, s := range m.subs {
		if Match(s.subject, subject) {
			targets = append(targets, s)
		}
	}
	m.mu.RUnlock()

	for _, s := range targets {
		// Each subscriber gets its own copy: handlers routinely enrich events.
		cp := e.Clone()
		select {
		case s.ch <- cp:
		case <-ctx.Done():
			return ctx.Err()
		default:
			m.mu.Lock()
			m.dropped++
			m.mu.Unlock()
			m.log.Error("bus subscriber overflow, event dropped",
				"subject", s.subject, "event_uid", e.Metadata.UID)
		}
	}
	return nil
}

// Subscribe registers a handler for a subject pattern.
func (m *Memory) Subscribe(subject string, h Handler) (Subscription, error) {
	if subject == "" {
		return nil, ErrBadSubject
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	m.nextID++
	s := &memSub{
		id:      m.nextID,
		subject: subject,
		ch:      make(chan *event.Event, m.bufSize),
		done:    make(chan struct{}),
		bus:     m,
	}
	m.subs[s.id] = s
	m.mu.Unlock()

	go func() {
		for {
			select {
			case e := <-s.ch:
				h(context.Background(), e)
			case <-s.done:
				// Drain what is already queued so a clean shutdown does not
				// discard evidence that was accepted for delivery.
				for {
					select {
					case e := <-s.ch:
						h(context.Background(), e)
					default:
						return
					}
				}
			}
		}
	}()
	return s, nil
}

// Stats reports subscriber count and dropped events.
func (m *Memory) Stats() (subscribers int, dropped uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.subs), m.dropped
}

// Close stops the bus and all subscriptions.
func (m *Memory) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	subs := make([]*memSub, 0, len(m.subs))
	for _, s := range m.subs {
		subs = append(subs, s)
	}
	m.mu.Unlock()

	for _, s := range subs {
		s.Unsubscribe()
	}
	return nil
}
