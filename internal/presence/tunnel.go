package presence

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// tunnel multiplexes many connections over one socket.
//
// Both ends use it, which keeps the two halves of the protocol from drifting
// apart: a bug in framing shows up on both sides at once, in tests, rather
// than in production on one of them.
type tunnel struct {
	conn net.Conn

	writeMu sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*streamConn
	closed  bool
	nextID  uint32
	// serverSide streams use even ids, client side odd, so the two ends can
	// both open streams without ever colliding.
	odd bool
}

func newTunnel(conn net.Conn, odd bool) *tunnel {
	t := &tunnel{conn: conn, streams: map[uint32]*streamConn{}, odd: odd}
	if odd {
		t.nextID = 1
	} else {
		t.nextID = 2
	}
	return t
}

// send writes one frame, serialised against other writers.
func (t *tunnel) send(f Frame) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return WriteFrame(t.conn, f)
}

// open allocates a stream initiated by this side.
func (t *tunnel) open(local, remote net.Addr) (*streamConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("presence: tunnel is closed")
	}
	if len(t.streams) >= MaxStreams {
		return nil, ErrTooManyStreams
	}
	id := t.nextID
	t.nextID += 2
	s := newStream(t, id, local, remote)
	t.streams[id] = s
	return s, nil
}

// accept registers a stream the peer opened.
func (t *tunnel) accept(id uint32, local, remote net.Addr) (*streamConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("presence: tunnel is closed")
	}
	if _, exists := t.streams[id]; exists {
		return nil, fmt.Errorf("presence: stream %d already exists", id)
	}
	if len(t.streams) >= MaxStreams {
		return nil, ErrTooManyStreams
	}
	s := newStream(t, id, local, remote)
	t.streams[id] = s
	return s, nil
}

func (t *tunnel) stream(id uint32) *streamConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams[id]
}

func (t *tunnel) remove(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.streams, id)
}

// Close tears down the tunnel and every stream on it. Either side dropping
// takes everything with it: a half-open overlay is worse than none, because it
// looks like a working decoy that records nothing.
func (t *tunnel) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	streams := make([]*streamConn, 0, len(t.streams))
	for _, s := range t.streams {
		streams = append(streams, s)
	}
	t.streams = map[uint32]*streamConn{}
	t.mu.Unlock()

	for _, s := range streams {
		s.closeLocal()
	}
	return t.conn.Close()
}

// streamConn is one tunnelled connection, presented as a net.Conn so that both
// the decoy farm and the agent's forwarder can treat it as an ordinary socket.
//
// "Ordinary" has to include deadlines. Every emulated service sets a read
// deadline so that an attacker who connects and says nothing is eventually
// dropped; a stream that ignored them would hold a goroutine, a session and a
// stream id for as long as the attacker cared to keep the socket open, and the
// tunnel would run out of streams long before anyone noticed.
type streamConn struct {
	t      *tunnel
	id     uint32
	local  net.Addr
	remote net.Addr

	// in carries what the peer sent, so that delivery never blocks the shared
	// frame reader. Handing bytes straight to the consumer would deadlock the
	// whole tunnel: the reader would wait for one slow consumer while the peer
	// waits for us to read, and both sides stop. This is the classic
	// head-of-line failure of a multiplexer without flow control.
	in chan []byte

	// readMu serialises readers; readBuf holds what one Read could not take.
	readMu  sync.Mutex
	readBuf []byte

	once      sync.Once
	closeOnce sync.Once

	mu       sync.Mutex
	inClosed bool
	deadline time.Time
	// wake is closed and replaced whenever the deadline changes, so that a
	// Read already blocked picks the new deadline up. net.Conn promises this.
	wake chan struct{}
}

// streamBuffer is how many chunks may be queued for one stream before it is
// treated as unable to keep up. It bounds memory: at most
// MaxStreams * streamBuffer * MaxFrameSize across the whole tunnel.
const streamBuffer = 16

func newStream(t *tunnel, id uint32, local, remote net.Addr) *streamConn {
	return &streamConn{
		t: t, id: id, local: local, remote: remote,
		in:   make(chan []byte, streamBuffer),
		wake: make(chan struct{}),
	}
}

// deliver queues data from the peer without ever blocking the frame reader.
//
// A stream that cannot keep up is closed rather than allowed to stall the
// tunnel. Losing one attacker session is a far better outcome than every decoy
// behind the overlay going silent.
func (s *streamConn) deliver(b []byte) {
	s.mu.Lock()
	if s.inClosed {
		s.mu.Unlock()
		return
	}
	select {
	case s.in <- b:
		s.mu.Unlock()
	default:
		s.mu.Unlock()
		s.Close()
	}
}

func (s *streamConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		if len(s.readBuf) > 0 {
			n := copy(b, s.readBuf)
			s.readBuf = s.readBuf[n:]
			if len(s.readBuf) == 0 {
				s.readBuf = nil
			}
			return n, nil
		}

		s.mu.Lock()
		deadline := s.deadline
		wake := s.wake
		s.mu.Unlock()

		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			left := time.Until(deadline)
			if left <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			// Stopped on every path out of this iteration rather than
			// deferred: a stream whose deadline is pushed forward on each
			// read would otherwise pile up one live timer per iteration.
			timer = time.NewTimer(left)
			timeout = timer.C
		}

		select {
		case chunk, ok := <-s.in:
			stopTimer(timer)
			// A closed channel still hands over what was already queued, so
			// the last thing the peer said arrives before the EOF does.
			if !ok {
				return 0, io.EOF
			}
			s.readBuf = chunk
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-wake:
			stopTimer(timer)
			// The deadline moved; work out the new one and wait again.
		}
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

func (s *streamConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	closed := s.inClosed
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > MaxFrameSize {
			chunk = chunk[:MaxFrameSize]
		}
		if err := s.t.send(Frame{Type: FrameData, Stream: s.id, Payload: chunk}); err != nil {
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

// Close tells the peer the stream is finished and releases it locally.
func (s *streamConn) Close() error {
	s.once.Do(func() {
		s.t.send(Frame{Type: FrameClose, Stream: s.id})
	})
	s.closeLocal()
	return nil
}

// closeLocal releases the stream without notifying the peer, for when the peer
// is the one that closed it.
//
// It closes only the inbound channel. A reader still drains whatever was
// queued and sees EOF after it -- the peer routinely answers and closes in the
// same breath, and discarding the buffer here would lose the answer.
func (s *streamConn) closeLocal() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.inClosed = true
		close(s.in)
		s.mu.Unlock()
		s.t.remove(s.id)
	})
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }

// SetDeadline applies to reads. Writes go out as frames on the shared socket,
// which carries its own write deadline, so a per-stream write deadline would
// promise something this transport cannot deliver.
func (s *streamConn) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	close(s.wake)
	s.wake = make(chan struct{})
	s.mu.Unlock()
	return nil
}

func (s *streamConn) SetReadDeadline(t time.Time) error  { return s.SetDeadline(t) }
func (s *streamConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*streamConn)(nil)

// tunnelAddr names an endpoint that exists only inside the overlay.
type tunnelAddr struct{ network, addr string }

func (a tunnelAddr) Network() string { return a.network }
func (a tunnelAddr) String() string  { return a.addr }

// parseAddr turns a wire address into something a decoy can attribute. An
// unparseable address becomes a named placeholder rather than an error: losing
// a whole session because an agent sent a malformed address would be worse than
// attributing it imprecisely.
func parseAddr(s string) net.Addr {
	if s == "" {
		return tunnelAddr{"tcp", "0.0.0.0:0"}
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return tunnelAddr{"tcp", s + ":0"}
	}
	return tunnelAddr{"tcp", s}
}
