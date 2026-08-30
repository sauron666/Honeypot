package compute

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func pveTestConfig() map[string]any {
	url := os.Getenv("PVE_URL")
	if url == "" {
		return nil
	}
	return map[string]any{
		"url":      url,
		"user":     os.Getenv("PVE_USER"),
		"password": os.Getenv("PVE_PASSWORD"),
		"node":     os.Getenv("PVE_NODE"),
	}
}

func TestProxmoxAPIProbe(t *testing.T) {
	cfg := pveTestConfig()
	if cfg == nil {
		t.Skip("PVE_URL not set — skipping live Proxmox test")
	}

	d, err := NewProxmox(cfg)
	if err != nil {
		t.Fatalf("NewProxmox: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := d.Probe(ctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	t.Log("Proxmox API probe OK")
}

func TestProxmoxAPIList(t *testing.T) {
	cfg := pveTestConfig()
	if cfg == nil {
		t.Skip("PVE_URL not set — skipping live Proxmox test")
	}

	d, err := NewProxmox(cfg)
	if err != nil {
		t.Fatalf("NewProxmox: %v", err)
	}
	px := d.(*Proxmox)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vms, err := px.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, vm := range vms {
		t.Logf("VM: %s handle=%s state=%s", vm.ID, vm.Handle, vm.State)
	}
}

func TestProxmoxNewRequiresNode(t *testing.T) {
	_, err := NewProxmox(map[string]any{"url": "https://localhost:8006", "user": "x"})
	if err == nil {
		t.Fatal("expected error when node is missing")
	}
}

func TestProxmoxNewRequiresAuth(t *testing.T) {
	_, err := NewProxmox(map[string]any{"url": "https://localhost:8006", "node": "x"})
	if err == nil {
		t.Fatal("expected error when neither user nor token is provided")
	}
}

func TestProxmoxCLIFallback(t *testing.T) {
	d, err := NewProxmox(map[string]any{"node": "test"})
	if err != nil {
		t.Fatalf("NewProxmox CLI mode: %v", err)
	}
	px := d.(*Proxmox)
	if px.api != nil {
		t.Fatal("expected nil api in CLI-only mode")
	}
}

func TestProxmoxFingerprintPinning(t *testing.T) {
	// A TLS server with a self-signed cert (exactly what Proxmox ships). Pinning
	// its fingerprint must let the client connect; pinning a different one must
	// make it refuse -- that is the MITM protection for a self-signed host.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"version":"8.4"}}`))
	}))
	defer srv.Close()

	// The server's real fingerprint.
	cert := srv.Certificate()
	realFP := fmt.Sprintf("%x", sha256Sum(cert.Raw))

	// Pinning the correct fingerprint: connection succeeds.
	api, err := newPVEAPI(srv.URL, "", "", "mirage@pve!t", "secret", false, realFP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.get(context.Background(), "/version"); err != nil {
		t.Fatalf("a correctly pinned fingerprint was rejected: %v", err)
	}

	// Pinning a wrong fingerprint: connection must be refused.
	bad, _ := newPVEAPI(srv.URL, "", "", "mirage@pve!t", "secret", false,
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff")
	if _, err := bad.get(context.Background(), "/version"); err == nil {
		t.Fatal("a wrong pinned fingerprint was accepted — MITM protection is broken")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	// A fingerprint copied from the PVE UI (colon-separated, upper) must match
	// one computed here (lower, no colons).
	if normalizeFingerprint("AA:BB:CC") != "aabbcc" {
		t.Fatalf("got %q", normalizeFingerprint("AA:BB:CC"))
	}
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
