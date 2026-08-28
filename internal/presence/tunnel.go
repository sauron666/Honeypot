package presence

import (
	"errors"
	"fmt"
	"io"
	"net"
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
type streamConn struct {
	t      *tunnel
	id     uint32
	local  net.Addr
	remote net.Addr

	pr *io.PipeReader
	pw *io.PipeWriter

	// in buffers what the peer sent, so that delivery never blocks the shared
	// frame reader. Handing bytes straight to the pipe would deadlock the whole
	// tunnel: the reader would wait for one slow consumer while the peer waits
	// for us to read, and both sides stop. This is the classic head-of-line
	// failure of a multiplexer without flow control.
	in     chan []byte
	pumpWG sync.WaitGroup

	once      sync.Once
	closeOnce sync.Once

	mu       sync.Mutex
	inClosed bool
	deadline time.Time
}

// streamBuffer is how many chunks may be queued for one stream before it is
// treated as unable to keep up. It bounds memory: at most
// MaxStreams * streamBuffer * MaxFrameSize across the whole tunnel.
const streamBuffer = 16

func newStream(t *tunnel, id uint32, local, remote net.Addr) *streamConn {
	pr, pw := io.Pipe()
	s := &streamConn{
		t: t, id: id, local: local, remote: remote, pr: pr, pw: pw,
		in: make(chan []byte, streamBuffer),
	}
	s.pumpWG.Add(1)
	go s.pump()
	return s
}

// pump moves buffered data into the pipe the consumer reads from.
func (s *streamConn) pump() {
	defer s.pumpWG.Done()
	for b := range s.in {
		if _, err := s.pw.Write(b); err != nil {
			return
		}
	}
	s.pw.Close()
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

func (s *streamConn) Read(b []byte) (int, error) { return s.pr.Read(b) }

func (s *streamConn) Write(b []byte) (int, error) {
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
func (s *streamConn) closeLocal() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.inClosed = true
		close(s.in)
		s.mu.Unlock()
		// The pump drains what is already queued and then closes the writer,
		// so the reader sees the remaining bytes and only then EOF. Closing the
		// reader here instead would discard a response that had already
		// arrived -- the peer answers and closes in the same breath, and the
		// close would win the race.
		s.t.remove(s.id)
	})
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }

// SetDeadline and friends are advisory here: the tunnel enforces its own
// timeouts, and a stream that outlives them dies with it. Services call these,
// so they must not fail.
func (s *streamConn) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
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
