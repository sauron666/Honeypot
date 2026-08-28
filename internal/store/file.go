package store

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// FileStore is the single-node evidence store: an append-only JSONL file plus a
// bounded in-memory window for fast queries.
//
// JSONL is a deliberate choice for profile P0. The evidence file is readable
// with grep and jq, survives a crash mid-write (a torn last line is detected
// and reported rather than silently accepted), and needs no server. Larger
// deployments swap this for ClickHouse behind the same interface.
type FileStore struct {
	mu sync.RWMutex

	path string
	f    *os.File
	w    *bufio.Writer

	chain *event.Chain

	// recent is a ring buffer of the newest events, oldest first.
	recent   []*event.Event
	capacity int
	byUID    map[string]*event.Event

	count      uint64
	bytes      int64
	truncated  bool // true once events have aged out of the memory window
	closed     bool
	syncEvery  int
	sinceSync  int
	verifiedAt int64
}

// FileOptions configures a FileStore.
type FileOptions struct {
	// MemoryWindow is how many recent events stay in RAM for querying.
	MemoryWindow int
	// SyncEvery forces an fsync after this many appends. 1 is safest and
	// slowest; 0 disables explicit syncing (the OS still flushes).
	SyncEvery int
}

// DefaultFileOptions favours durability of evidence over throughput: a honeypot
// that loses the last few events of an intrusion has lost the interesting part.
func DefaultFileOptions() FileOptions {
	return FileOptions{MemoryWindow: 200_000, SyncEvery: 1}
}

// OpenFile opens or creates an evidence file, replaying it to restore the chain
// head and the in-memory window.
func OpenFile(path string, opts FileOptions) (*FileStore, error) {
	if opts.MemoryWindow <= 0 {
		opts.MemoryWindow = DefaultFileOptions().MemoryWindow
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: create directory: %w", err)
	}

	s := &FileStore{
		path:      path,
		capacity:  opts.MemoryWindow,
		byUID:     make(map[string]*event.Event),
		syncEvery: opts.SyncEvery,
	}
	if err := s.replay(); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	s.f = f
	s.w = bufio.NewWriterSize(f, 64*1024)

	if fi, err := f.Stat(); err == nil {
		s.bytes = fi.Size()
	}
	return s, nil
}

// replay reads an existing evidence file to restore state. A truncated final
// line (a crash mid-append) is reported, not hidden.
func (s *FileStore) replay() error {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		s.chain = event.NewChain()
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: replay %s: %w", s.path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var lastSeq uint64
	var lastHash string
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		e, err := event.Decode(raw)
		if err != nil {
			return fmt.Errorf("store: %s line %d is corrupt (crash during append?): %w", s.path, line, err)
		}
		if e.Mirage.Chain != nil {
			lastSeq = e.Mirage.Chain.Seq
			lastHash = e.Mirage.Chain.Hash
		}
		s.remember(e)
		s.count++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("store: read %s: %w", s.path, err)
	}
	s.chain = event.ResumeChain(lastSeq, lastHash)
	return nil
}

// remember inserts into the memory window, evicting the oldest when full.
func (s *FileStore) remember(e *event.Event) {
	if len(s.recent) == s.capacity {
		evicted := s.recent[0]
		copy(s.recent, s.recent[1:])
		s.recent[len(s.recent)-1] = e
		delete(s.byUID, evicted.Metadata.UID)
		s.truncated = true
	} else {
		s.recent = append(s.recent, e)
	}
	s.byUID[e.Metadata.UID] = e
}

// Append seals and persists an event.
func (s *FileStore) Append(ctx context.Context, e *event.Event) error {
	if e == nil {
		return fmt.Errorf("store: nil event")
	}
	if err := e.Validate(); err != nil {
		return fmt.Errorf("store: refusing to persist invalid event: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}

	if err := s.chain.Seal(e); err != nil {
		return fmt.Errorf("store: seal: %w", err)
	}
	raw, err := event.CanonicalJSON(e)
	if err != nil {
		return fmt.Errorf("store: encode: %w", err)
	}
	raw = append(raw, '\n')
	n, err := s.w.Write(raw)
	if err != nil {
		return fmt.Errorf("store: write: %w", err)
	}
	s.bytes += int64(n)
	s.count++
	s.sinceSync++

	if s.syncEvery > 0 && s.sinceSync >= s.syncEvery {
		if err := s.flushLocked(); err != nil {
			return err
		}
	}
	s.remember(e)
	return nil
}

func (s *FileStore) flushLocked() error {
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("store: flush: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("store: fsync: %w", err)
	}
	s.sinceSync = 0
	return nil
}

// Flush forces buffered data to disk.
func (s *FileStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.flushLocked()
}

// Query returns matching events, newest first unless q.Ascending is set. When
// the requested time range predates the memory window, the durable file is
// scanned instead so that evidence is never invisible just because it is old.
func (s *FileStore) Query(ctx context.Context, q Query) ([]*event.Event, error) {
	s.mu.RLock()
	needFile := s.truncated && s.needsOlderThanMemory(q)
	s.mu.RUnlock()

	if needFile {
		return s.queryFile(ctx, q)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*event.Event, 0, q.limit())
	if q.Ascending {
		for _, e := range s.recent {
			if !q.Matches(e) {
				continue
			}
			out = append(out, e)
		}
	} else {
		for i := len(s.recent) - 1; i >= 0; i-- {
			if !q.Matches(s.recent[i]) {
				continue
			}
			out = append(out, s.recent[i])
		}
	}
	return page(out, q), nil
}

// needsOlderThanMemory reports whether the query reaches back past the window.
func (s *FileStore) needsOlderThanMemory(q Query) bool {
	if len(s.recent) == 0 {
		return true
	}
	if q.Since.IsZero() {
		// An unbounded query only needs the file if the window cannot satisfy
		// the requested page.
		return q.Offset+q.limit() > len(s.recent)
	}
	return q.Since.UnixMilli() < s.recent[0].Time
}

func (s *FileStore) queryFile(ctx context.Context, q Query) ([]*event.Event, error) {
	s.mu.RLock()
	path := s.path
	s.mu.RUnlock()
	if err := s.Flush(); err != nil && err != ErrClosed {
		return nil, err
	}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var out []*event.Event
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if len(sc.Bytes()) == 0 {
			continue
		}
		e, err := event.Decode(sc.Bytes())
		if err != nil {
			continue // a corrupt tail must not hide the records before it
		}
		if q.Matches(e) {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !q.Ascending {
		sort.SliceStable(out, func(i, j int) bool { return out[i].Time > out[j].Time })
	}
	return page(out, q), nil
}

func page(in []*event.Event, q Query) []*event.Event {
	if q.Offset >= len(in) {
		return []*event.Event{}
	}
	in = in[q.Offset:]
	if len(in) > q.limit() {
		in = in[:q.limit()]
	}
	return in
}

// Get returns one event by UID.
func (s *FileStore) Get(ctx context.Context, uid string) (*event.Event, error) {
	s.mu.RLock()
	e, ok := s.byUID[uid]
	s.mu.RUnlock()
	if ok {
		return e, nil
	}
	res, err := s.queryFile(ctx, Query{Limit: 1, Search: uid})
	if err != nil {
		return nil, err
	}
	for _, cand := range res {
		if cand.Metadata.UID == uid {
			return cand, nil
		}
	}
	return nil, ErrNotFound
}

// Head returns the chain position.
func (s *FileStore) Head() (uint64, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.chain.Head()
}

// Verify replays the durable chain end to end. This is the operation an
// analyst runs before exporting evidence.
func (s *FileStore) Verify(ctx context.Context) error {
	if err := s.Flush(); err != nil && err != ErrClosed {
		return err
	}
	s.mu.RLock()
	path := s.path
	s.mu.RUnlock()

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	prev := event.GenesisHash
	idx := 0
	// Verify streams one event at a time so that a multi-gigabyte evidence file
	// can be checked on a machine that cannot hold it in memory.
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if len(sc.Bytes()) == 0 {
			continue
		}
		e, err := event.Decode(sc.Bytes())
		if err != nil {
			return fmt.Errorf("store: line %d is corrupt: %w", idx+1, err)
		}
		if err := event.Verify([]*event.Event{e}, prev); err != nil {
			return err
		}
		prev = e.Mirage.Chain.Hash
		idx++
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return err
	}

	s.mu.Lock()
	s.verifiedAt = time.Now().UnixMilli()
	s.mu.Unlock()
	return nil
}

// Stats reports store state.
func (s *FileStore) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seq, hash := s.chain.Head()
	st := Stats{
		Events:     s.count,
		InMemory:   len(s.recent),
		Bytes:      s.bytes,
		HeadSeq:    seq,
		HeadHash:   hash,
		Truncated:  s.truncated,
		VerifiedAt: s.verifiedAt,
	}
	if len(s.recent) > 0 {
		st.Oldest = s.recent[0].Time
		st.Newest = s.recent[len(s.recent)-1].Time
	}
	return st
}

// Close flushes and closes the evidence file.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.w != nil {
		if err := s.w.Flush(); err != nil {
			return err
		}
	}
	if s.f != nil {
		if err := s.f.Sync(); err != nil {
			return err
		}
		return s.f.Close()
	}
	return nil
}

var _ EventStore = (*FileStore)(nil)
