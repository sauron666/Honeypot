package compute

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// fakeVCenter is a minimal stand-in for the vSphere Automation REST API, enough
// to exercise the driver's request/response handling without a live vCenter.
// This is how the driver is validated until a real endpoint is available.
func fakeVCenter(t *testing.T) *httptest.Server {
	t.Helper()
	vms := []vmSummary{
		{VM: "vm-101", Name: "web01", PowerState: "POWERED_OFF"},
		{VM: "vm-102", Name: "tmpl-ubuntu", PowerState: "POWERED_OFF"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/session", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u == "" || p == "" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode("session-token-abc")
	})
	mux.HandleFunc("GET /api/vcenter/vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("vmware-api-session-id") == "" {
			w.WriteHeader(401)
			return
		}
		name := r.URL.Query().Get("names")
		out := []vmSummary{}
		for _, vm := range vms {
			if name == "" || vm.Name == name {
				out = append(out, vm)
			}
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /api/vcenter/vm/{vm}/power", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /api/vcenter/vm/{vm}/snapshots", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		json.NewEncoder(w).Encode("snapshot-1")
	})
	return httptest.NewServer(mux)
}

func newTestVSphere(t *testing.T, url string) *VSphere {
	t.Helper()
	d, err := NewVSphere(map[string]any{
		"url": url, "user": "administrator@vsphere.local", "password": "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*VSphere)
}

func TestVSphereProbeAndList(t *testing.T) {
	srv := fakeVCenter(t)
	defer srv.Close()
	v := newTestVSphere(t, srv.URL)

	if err := v.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	list, err := v.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(list))
	}
}

func TestVSphereStatusAndPower(t *testing.T) {
	srv := fakeVCenter(t)
	defer srv.Close()
	v := newTestVSphere(t, srv.URL)

	st, err := v.Status(context.Background(), "web01")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != drivers.StateStopped || st.Handle != "vsphere/vm-101" {
		t.Fatalf("unexpected status: %+v", st)
	}
	if err := v.Start(context.Background(), "web01"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := v.Snapshot(context.Background(), "web01", "clean"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
}

func TestVSphereStatusOfUnknownIsAbsent(t *testing.T) {
	srv := fakeVCenter(t)
	defer srv.Close()
	v := newTestVSphere(t, srv.URL)
	st, _ := v.Status(context.Background(), "does-not-exist")
	if st.State != drivers.StateAbsent {
		t.Fatalf("unknown VM should be absent, got %q", st.State)
	}
}

func TestVSphereCreateAdoptsExisting(t *testing.T) {
	srv := fakeVCenter(t)
	defer srv.Close()
	v := newTestVSphere(t, srv.URL)
	// web01 already exists; Create must adopt it, not fail.
	st, err := v.Create(context.Background(), drivers.DecoySpec{ID: "dcy-web", Name: "web01"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Handle != "vsphere/vm-101" {
		t.Fatalf("expected to adopt vm-101, got %q", st.Handle)
	}
}

func TestVSphereConfigValidation(t *testing.T) {
	if _, err := NewVSphere(map[string]any{"user": "a", "password": "b"}); err == nil {
		t.Error("expected error when url is missing")
	}
	if _, err := NewVSphere(map[string]any{"url": "https://vc"}); err == nil {
		t.Error("expected error when credentials are missing")
	}
}

func TestVSphereIsExperimental(t *testing.T) {
	if !VSphereInfo().Experimental {
		t.Error("vSphere driver must be marked experimental until validated on a live vCenter")
	}
	if !strings.Contains(strings.ToLower(VSphereInfo().Summary), "experimental") {
		t.Error("the summary should say so plainly")
	}
}
