// Command mirage-sensor is the in-guest collector for full-OS decoys.
//
// It watches process execution inside the decoy and forwards each event to the
// MIRAGE director's agent observer (see internal/drivers/observer/agent.go), so
// every command an attacker runs — ls, id, sudo su, powershell iwr … — reaches
// the evidence chain on ANY hypervisor, without agentless VMI.
//
// It is deliberately small and single-purpose. On a real corporate machine the
// equivalent telemetry comes from auditd or Sysmon; this binary plays that role
// for a decoy and can be named to blend in.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// forwarder batches sightings and ships them to the director's /ingest endpoint.
// Batching keeps a busy decoy from making one request per exec; a bounded queue
// and drop-on-full keep the sensor from ever stalling the workload it watches.
type forwarder struct {
	url    string
	token  string
	client *http.Client

	mu    sync.Mutex
	queue []drivers.Sighting
	max   int
}

func newForwarder(directorURL, token string) *forwarder {
	return &forwarder{
		url:    directorURL + "/ingest",
		token:  token,
		client: &http.Client{Timeout: 15 * time.Second},
		max:    4096,
	}
}

// enqueue adds a sighting, dropping the oldest if the queue is full so the
// sensor never blocks the process it is observing.
func (f *forwarder) enqueue(s drivers.Sighting) {
	f.mu.Lock()
	if len(f.queue) >= f.max {
		f.queue = f.queue[1:]
	}
	f.queue = append(f.queue, s)
	f.mu.Unlock()
}

// drain returns and clears the current batch.
func (f *forwarder) drain() []drivers.Sighting {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return nil
	}
	batch := f.queue
	f.queue = nil
	return batch
}

// flush ships the current batch. On failure it re-queues the batch so nothing
// is lost across a transient director outage.
func (f *forwarder) flush(ctx context.Context) error {
	batch := f.drain()
	if len(batch) == 0 {
		return nil
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", f.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		f.requeue(batch)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		f.requeue(batch)
		return fmt.Errorf("director returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// requeue puts a failed batch back at the front, bounded by max.
func (f *forwarder) requeue(batch []drivers.Sighting) {
	f.mu.Lock()
	f.queue = append(batch, f.queue...)
	if len(f.queue) > f.max {
		f.queue = f.queue[len(f.queue)-f.max:]
	}
	f.mu.Unlock()
}

// run flushes on an interval until the context ends.
func (f *forwarder) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			f.flush(flushCtx)
			cancel()
			return
		case <-t.C:
			if err := f.flush(ctx); err != nil {
				logf("flush: %v", err)
			}
		}
	}
}
