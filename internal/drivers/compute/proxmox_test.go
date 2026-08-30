package compute

import (
	"context"
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
