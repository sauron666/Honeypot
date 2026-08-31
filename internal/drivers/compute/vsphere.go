package compute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// VSphereInfo describes the VMware vSphere compute driver.
//
// It is marked experimental: the code is exercised by unit tests against
// synthetic vCenter responses, but it has NOT yet been validated against a live
// vCenter (unlike the Proxmox driver, validated on PVE 8.4). Honesty about that
// matters — an operator must know which drivers are field-proven.
func VSphereInfo() drivers.Info {
	return drivers.Info{
		Name: "vsphere",
		Kind: drivers.KindCompute,
		Summary: "Full-OS decoys on VMware vSphere (vCenter 7/8) via the vSphere " +
			"Automation REST API. Session auth, TLS fingerprint pinning, power " +
			"control, status/list, snapshot and revert. EXPERIMENTAL: unit-tested " +
			"against synthetic responses, not yet validated on a live vCenter.",
		Capabilities: []drivers.Capability{
			drivers.CapClone, drivers.CapSnapshot, drivers.CapRevert, drivers.CapFullOS,
		},
		Experimental: true,
	}
}

// VSphere drives vCenter through the vSphere Automation REST API (the `/api`
// namespace on vCenter 7.0u2+). It authenticates once, caches the session id,
// and pins the TLS fingerprint the same way the Proxmox driver does, because
// vCenter also ships a self-signed certificate by default.
type VSphere struct {
	api    *vcAPI
	folder string // optional VM folder / resource hint recorded on created decoys
}

// NewVSphere builds the driver. Config keys:
//
//	"url"             — required, vCenter base URL (e.g. "https://vcenter.example")
//	"user"            — required, e.g. "administrator@vsphere.local"
//	"password"        — required
//	"verify_tls"      — verify the certificate chain (default false; vCenter is self-signed)
//	"tls_fingerprint" — pin the vCenter cert SHA-256 (recommended with self-signed)
//	"folder"          — optional VM folder id recorded on created decoys
func NewVSphere(cfg map[string]any) (drivers.Driver, error) {
	get := func(k, def string) string {
		if v, ok := cfg[k].(string); ok && v != "" {
			return v
		}
		return def
	}
	getBool := func(k string, def bool) bool {
		if v, ok := cfg[k].(bool); ok {
			return v
		}
		if v, ok := cfg[k].(string); ok {
			return v == "true" || v == "1" || v == "yes"
		}
		return def
	}

	base := get("url", "")
	if base == "" {
		return nil, fmt.Errorf("compute/vsphere: \"url\" is required (the vCenter base URL, e.g. https://vcenter.example)")
	}
	user := get("user", "")
	pass := get("password", "")
	if user == "" || pass == "" {
		return nil, fmt.Errorf("compute/vsphere: \"user\" and \"password\" are required")
	}

	api := &vcAPI{
		baseURL: trimSlash(base),
		user:    user,
		pass:    pass,
		client: &http.Client{
			Timeout:   2 * time.Minute,
			Transport: &http.Transport{TLSClientConfig: tlsConfigFor(getBool("verify_tls", false), get("tls_fingerprint", ""))},
		},
	}
	return &VSphere{api: api, folder: get("folder", "")}, nil
}

func (v *VSphere) Info() drivers.Info { return VSphereInfo() }
func (v *VSphere) Close() error       { return nil }

func (v *VSphere) Probe(ctx context.Context) error {
	if err := v.api.authenticate(ctx); err != nil {
		return fmt.Errorf("compute/vsphere: cannot authenticate to vCenter: %w", err)
	}
	// A cheap authenticated call that exists on every vCenter.
	if _, err := v.api.do(ctx, "GET", "/api/vcenter/vm", nil); err != nil {
		return fmt.Errorf("compute/vsphere: authenticated but cannot list VMs: %w", err)
	}
	return nil
}

// vmSummary is one row of GET /api/vcenter/vm.
type vmSummary struct {
	VM         string `json:"vm"`
	Name       string `json:"name"`
	PowerState string `json:"power_state"`
}

// findByName resolves a decoy id (its VM name) to a vCenter managed object id.
func (v *VSphere) findByName(ctx context.Context, name string) (vmSummary, bool, error) {
	raw, err := v.api.do(ctx, "GET", "/api/vcenter/vm?names="+url.QueryEscape(name), nil)
	if err != nil {
		return vmSummary{}, false, err
	}
	var list []vmSummary
	if err := json.Unmarshal(raw, &list); err != nil {
		return vmSummary{}, false, fmt.Errorf("compute/vsphere: parse vm list: %w", err)
	}
	for _, s := range list {
		if s.Name == name {
			return s, true, nil
		}
	}
	if len(list) == 1 {
		return list[0], true, nil
	}
	return vmSummary{}, false, nil
}

func stateOf(power string) drivers.DecoyState {
	if power == "POWERED_ON" {
		return drivers.StateRunning
	}
	return drivers.StateStopped
}

// Create adopts an existing VM matching spec.Name, or clones one from the named
// template. Adoption first is deliberate: a common vSphere workflow pre-creates
// decoys from a template, and MIRAGE then manages their lifecycle.
func (v *VSphere) Create(ctx context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	if s, ok, err := v.findByName(ctx, spec.Name); err != nil {
		return drivers.DecoyStatus{}, err
	} else if ok {
		return drivers.DecoyStatus{
			ID: spec.ID, Handle: "vsphere/" + s.VM,
			State: stateOf(s.PowerState), CreatedAt: time.Now(),
		}, nil
	}

	if spec.Template == "" {
		return drivers.DecoyStatus{}, fmt.Errorf(
			"compute/vsphere: VM %q not found and no template given to clone from", spec.Name)
	}
	src, ok, err := v.findByName(ctx, spec.Template)
	if err != nil {
		return drivers.DecoyStatus{}, err
	}
	if !ok {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/vsphere: clone source template %q not found", spec.Template)
	}
	// vSphere 8 REST clone: POST /api/vcenter/vm?action=clone.
	body := map[string]any{
		"source": src.VM,
		"name":   spec.Name,
	}
	if v.folder != "" {
		body["placement"] = map[string]any{"folder": v.folder}
	}
	raw, err := v.api.do(ctx, "POST", "/api/vcenter/vm?action=clone", body)
	if err != nil {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/vsphere: clone %q from %q: %w", spec.Name, spec.Template, err)
	}
	var newVM string
	json.Unmarshal(raw, &newVM) // the clone returns the new VM id as a JSON string
	return drivers.DecoyStatus{
		ID: spec.ID, Handle: "vsphere/" + newVM,
		State: drivers.StateCreated, CreatedAt: time.Now(),
	}, nil
}

func (v *VSphere) power(ctx context.Context, id, action string) error {
	s, ok, err := v.findByName(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", drivers.ErrNoOp, id)
	}
	_, err = v.api.do(ctx, "POST", "/api/vcenter/vm/"+s.VM+"/power?action="+action, nil)
	return err
}

func (v *VSphere) Start(ctx context.Context, id string) error { return v.power(ctx, id, "start") }
func (v *VSphere) Stop(ctx context.Context, id string) error  { return v.power(ctx, id, "stop") }

func (v *VSphere) Destroy(ctx context.Context, id string) error {
	s, ok, err := v.findByName(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	_, err = v.api.do(ctx, "DELETE", "/api/vcenter/vm/"+s.VM, nil)
	return err
}

func (v *VSphere) Status(ctx context.Context, id string) (drivers.DecoyStatus, error) {
	s, ok, err := v.findByName(ctx, id)
	if err != nil || !ok {
		return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
	}
	return drivers.DecoyStatus{ID: id, Handle: "vsphere/" + s.VM, State: stateOf(s.PowerState)}, nil
}

func (v *VSphere) List(ctx context.Context) ([]drivers.DecoyStatus, error) {
	raw, err := v.api.do(ctx, "GET", "/api/vcenter/vm", nil)
	if err != nil {
		return nil, err
	}
	var list []vmSummary
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("compute/vsphere: parse vm list: %w", err)
	}
	out := make([]drivers.DecoyStatus, 0, len(list))
	for _, s := range list {
		out = append(out, drivers.DecoyStatus{
			ID: s.Name, Handle: "vsphere/" + s.VM, State: stateOf(s.PowerState),
		})
	}
	return out, nil
}

func (v *VSphere) Snapshot(ctx context.Context, id, name string) error {
	s, ok, err := v.findByName(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("compute/vsphere: no VM %q to snapshot", id)
	}
	// vSphere 8 REST: POST /api/vcenter/vm/{vm}/snapshots.
	body := map[string]any{"name": name, "description": "mirage decoy snapshot"}
	_, err = v.api.do(ctx, "POST", "/api/vcenter/vm/"+s.VM+"/snapshots", body)
	return err
}

func (v *VSphere) Revert(ctx context.Context, id, name string) error {
	s, ok, err := v.findByName(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("compute/vsphere: no VM %q to revert", id)
	}
	_, err = v.api.do(ctx, "POST", "/api/vcenter/vm/"+s.VM+"/snapshots/"+url.PathEscape(name)+"?action=revert", nil)
	return err
}

var _ drivers.ComputeDriver = (*VSphere)(nil)

// ---------------------------------------------------------------------------
// vСenter REST client
// ---------------------------------------------------------------------------

type vcAPI struct {
	baseURL string
	user    string
	pass    string
	client  *http.Client

	mu      sync.Mutex
	session string
	sessExp time.Time
}

// authenticate obtains a session id from POST /api/session (basic auth) and
// caches it. vCenter sessions idle out; we refresh well within that.
func (a *vcAPI) authenticate(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session != "" && time.Now().Before(a.sessExp) {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/api/session", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(a.user, a.pass)
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("vCenter session request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("vCenter session failed (HTTP %d): %s", resp.StatusCode, truncate(body, 200))
	}
	var sid string
	if err := json.Unmarshal(body, &sid); err != nil || sid == "" {
		return fmt.Errorf("vCenter session: unexpected response: %s", truncate(body, 200))
	}
	a.session = sid
	a.sessExp = time.Now().Add(20 * time.Minute)
	return nil
}

// do performs an authenticated request, refreshing the session once on a 401.
func (a *vcAPI) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	if err := a.authenticate(ctx); err != nil {
		return nil, err
	}
	raw, status, err := a.doOnce(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if status == 401 {
		// Session expired: drop it and retry once.
		a.mu.Lock()
		a.session = ""
		a.mu.Unlock()
		if err := a.authenticate(ctx); err != nil {
			return nil, err
		}
		raw, status, err = a.doOnce(ctx, method, path, body)
		if err != nil {
			return nil, err
		}
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("vCenter %s %s: HTTP %d: %s", method, path, status, truncate(raw, 300))
	}
	return raw, nil
}

func (a *vcAPI) doOnce(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	a.mu.Lock()
	sid := a.session
	a.mu.Unlock()
	req.Header.Set("vmware-api-session-id", sid)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
