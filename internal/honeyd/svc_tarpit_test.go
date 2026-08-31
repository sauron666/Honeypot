package honeyd

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestTarpitIsRegistered(t *testing.T) {
	if _, ok := serviceRegistry["tarpit"]; !ok {
		t.Fatal("tarpit service should be registered")
	}
}

func TestTarpitTricklesAndRecordsTimeConsumed(t *testing.T) {
	p, _ := BuildPersona("linux/web", "seed")
	col := &collector{}
	sess := newTestSession(p, col)

	svc, err := newTarpit(p, map[string]any{
		"hold_max":      "300ms",
		"trickle_every": "20ms",
	})
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		svc.Serve(context.Background(), server, sess)
		close(done)
	}()

	// The attacker's tool sits reading the slow banner.
	var got int64
	go func() {
		buf := make([]byte, 64)
		for {
			client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := client.Read(buf)
			atomic.AddInt64(&got, int64(n))
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tarpit held far longer than hold_max; it should have released")
	}
	server.Close()
	client.Close()

	if atomic.LoadInt64(&got) == 0 {
		t.Fatal("the tarpit should have trickled at least one byte to keep the client waiting")
	}

	// It must record that it held the attacker (the ROI signal).
	released := false
	for _, e := range col.all() {
		if _, ok := e.Get("held_seconds"); ok {
			released = true
		}
	}
	if !released {
		t.Fatal("the tarpit must emit a release event with held_seconds (attacker time consumed)")
	}
}

func TestTarpitReleasesWhenAttackerLeaves(t *testing.T) {
	p, _ := BuildPersona("linux/web", "seed")
	col := &collector{}
	sess := newTestSession(p, col)
	svc, _ := newTarpit(p, map[string]any{"hold_max": "10s", "trickle_every": "20ms"})

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { svc.Serve(context.Background(), server, sess); close(done) }()

	// The attacker hangs up almost immediately; the tarpit must notice and let
	// go rather than holding a dead socket for the full hold_max.
	time.Sleep(60 * time.Millisecond)
	client.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tarpit did not release after the attacker disconnected")
	}
	server.Close()
}
