package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/sauron666/Honeypot/internal/drivers"
)

func TestForwarderBatchesAndAuthenticates(t *testing.T) {
	var mu sync.Mutex
	var got []drivers.Sighting
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var batch []drivers.Sighting
		json.Unmarshal(body, &batch)
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd := newForwarder(srv.URL, "tok")
	fwd.enqueue(drivers.Sighting{DecoyID: "d1", Kind: "process", CommandLine: "id"})
	fwd.enqueue(drivers.Sighting{DecoyID: "d1", Kind: "process", CommandLine: "sudo su"})

	if err := fwd.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("expected 2 sightings delivered, got %d", len(got))
	}
	if gotToken != "Bearer tok" {
		t.Fatalf("token not sent: %q", gotToken)
	}
}

func TestForwarderRequeuesOnFailure(t *testing.T) {
	// Point at a closed server so the flush fails; the batch must be preserved.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	fwd := newForwarder(srv.URL, "tok")
	fwd.enqueue(drivers.Sighting{DecoyID: "d1", CommandLine: "whoami"})
	if err := fwd.flush(context.Background()); err == nil {
		t.Fatal("expected an error from a 500")
	}
	if len(fwd.drain()) != 1 {
		t.Fatal("failed batch must be re-queued, not lost")
	}
}

func TestForwarderDropsOldestWhenFull(t *testing.T) {
	fwd := newForwarder("http://x", "t")
	fwd.max = 3
	for i := 0; i < 5; i++ {
		fwd.enqueue(drivers.Sighting{DecoyID: "d", PID: i})
	}
	batch := fwd.drain()
	if len(batch) != 3 {
		t.Fatalf("queue should cap at 3, got %d", len(batch))
	}
	// The oldest two (PID 0,1) were dropped; 2,3,4 remain.
	if batch[0].PID != 2 {
		t.Fatalf("expected oldest dropped, front PID=%d", batch[0].PID)
	}
}
