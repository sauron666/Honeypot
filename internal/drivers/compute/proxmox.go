package compute

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// ProxmoxInfo describes the Proxmox VE compute driver.
func ProxmoxInfo() drivers.Info {
	return drivers.Info{
		Name: "proxmox",
		Kind: drivers.KindCompute,
		Summary: "Full-OS decoys on Proxmox VE. Supports linked clones from " +
			"templates, snapshots and revert. Two modes: REST API (remote, " +
			"no pvesh needed) and pvesh CLI (on the PVE node itself).",
		Capabilities: []drivers.Capability{
			drivers.CapClone, drivers.CapLinkedClone, drivers.CapSnapshot,
			drivers.CapRevert, drivers.CapFullOS,
		},
	}
}

// Proxmox drives Proxmox VE through its REST API (remote) or the pvesh CLI
// (local). The REST mode is preferred: it works from any machine, needs only
// credentials, and is what the GUI uses.
type Proxmox struct {
	node string
	pool string

	// REST API mode
	api *pveAPI

	// pvesh CLI fallback
	pvesh string
	run   runner
}

// NewProxmox builds the driver. Config keys:
//
//	"node"     — required, the PVE node name (the one /nodes lists)
//	"url"      — PVE API URL (e.g. "https://192.168.1.100:8006"); enables REST mode
//	"user"     — API user (e.g. "root@pam")
//	"password" — password for ticket auth
//	"token_id" — API token ID (e.g. "root@pam!mirage"); alternative to user/password
//	"token_secret" — API token secret
//	"verify_tls" — verify TLS certificates (default false for self-signed PVE certs)
//	"pool"     — resource pool for decoy VMs (default "mirage")
//	"pvesh"    — pvesh binary path (CLI mode fallback)
func NewProxmox(cfg map[string]any) (drivers.Driver, error) {
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

	node := get("node", "")
	if node == "" {
		return nil, fmt.Errorf("compute/proxmox: \"node\" is required — the PVE node name " +
			"(the one `pvesh get /nodes` lists)")
	}

	p := &Proxmox{
		node:  node,
		pool:  get("pool", "mirage"),
		pvesh: get("pvesh", "pvesh"),
		run:   execRunner{timeout: 5 * time.Minute},
	}

	apiURL := get("url", "")
	if apiURL != "" {
		user := get("user", "")
		password := get("password", "")
		tokenID := get("token_id", "")
		tokenSecret := get("token_secret", "")
		verifyTLS := getBool("verify_tls", false)

		api, err := newPVEAPI(apiURL, user, password, tokenID, tokenSecret, verifyTLS)
		if err != nil {
			return nil, fmt.Errorf("compute/proxmox: %w", err)
		}
		p.api = api
	}

	return p, nil
}

func (p *Proxmox) Info() drivers.Info { return ProxmoxInfo() }

func (p *Proxmox) Probe(ctx context.Context) error {
	if p.api != nil {
		_, err := p.apiGet(ctx, "/nodes/"+p.node+"/status")
		if err != nil {
			return fmt.Errorf("compute/proxmox: cannot reach node %q via API: %w", p.node, err)
		}
		return nil
	}
	if !binaryExists(p.pvesh) {
		return fmt.Errorf("compute/proxmox: %q not found on PATH and no API URL configured; "+
			"set \"url\" for remote access or run on the PVE node", p.pvesh)
	}
	if _, err := p.pveshGet(ctx, "/nodes/"+p.node+"/status"); err != nil {
		return fmt.Errorf("compute/proxmox: cannot reach node %q: %w", p.node, err)
	}
	return nil
}

func (p *Proxmox) Close() error { return nil }

func (p *Proxmox) Create(ctx context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	vmid, err := p.nextVMID(ctx)
	if err != nil {
		return drivers.DecoyStatus{}, err
	}

	params := map[string]string{
		"newid": vmid,
		"name":  spec.Name,
		"full":  "0",
	}
	if p.pool != "" {
		params["pool"] = p.pool
	}

	clonePath := fmt.Sprintf("/nodes/%s/qemu/%s/clone", p.node, spec.Template)
	if err := p.apiPost(ctx, clonePath, params); err != nil {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/proxmox: clone %s from template %s: %w",
			spec.ID, spec.Template, err)
	}

	if spec.CPUs > 0 {
		p.apiPut(ctx, p.vmPath(vmid), map[string]string{"cores": fmt.Sprint(spec.CPUs)})
	}
	if spec.MemoryMB > 0 {
		p.apiPut(ctx, p.vmPath(vmid), map[string]string{"memory": fmt.Sprint(spec.MemoryMB)})
	}

	return drivers.DecoyStatus{
		ID: spec.ID, Handle: "proxmox/" + vmid,
		State: drivers.StateCreated, CreatedAt: time.Now(),
	}, nil
}

func (p *Proxmox) Start(ctx context.Context, id string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	return p.apiPost(ctx, p.vmPath(vmid)+"/status/start", nil)
}

func (p *Proxmox) Stop(ctx context.Context, id string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	return p.apiPost(ctx, p.vmPath(vmid)+"/status/stop", nil)
}

func (p *Proxmox) Destroy(ctx context.Context, id string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	return p.apiDelete(ctx, p.vmPath(vmid)+"?purge=1")
}

func (p *Proxmox) Status(ctx context.Context, id string) (drivers.DecoyStatus, error) {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
	}
	raw, err := p.apiGet(ctx, p.vmPath(vmid)+"/status/current")
	if err != nil {
		return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
	}
	var status struct {
		Status string `json:"status"`
	}
	json.Unmarshal(raw, &status)
	st := drivers.StateStopped
	if status.Status == "running" {
		st = drivers.StateRunning
	}
	return drivers.DecoyStatus{ID: id, Handle: "proxmox/" + vmid, State: st}, nil
}

func (p *Proxmox) List(ctx context.Context) ([]drivers.DecoyStatus, error) {
	raw, err := p.apiGet(ctx, fmt.Sprintf("/nodes/%s/qemu", p.node))
	if err != nil {
		return nil, err
	}
	var vms []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &vms); err != nil {
		return nil, fmt.Errorf("compute/proxmox: parse vm list: %w", err)
	}

	var result []drivers.DecoyStatus
	for _, vm := range vms {
		if p.pool != "" && !p.inPool(ctx, fmt.Sprint(vm.VMID)) {
			continue
		}
		st := drivers.StateStopped
		if vm.Status == "running" {
			st = drivers.StateRunning
		}
		result = append(result, drivers.DecoyStatus{
			ID: vm.Name, Handle: fmt.Sprintf("proxmox/%d", vm.VMID), State: st,
		})
	}
	return result, nil
}

func (p *Proxmox) Snapshot(ctx context.Context, id, name string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	return p.apiPost(ctx, p.vmPath(vmid)+"/snapshot", map[string]string{
		"snapname": name, "vmstate": "1",
	})
}

func (p *Proxmox) Revert(ctx context.Context, id, name string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	return p.apiPost(ctx, fmt.Sprintf("%s/snapshot/%s/rollback", p.vmPath(vmid), name), nil)
}

// ---------------------------------------------------------------------------
// Unified helpers: route to REST API or pvesh CLI
// ---------------------------------------------------------------------------

func (p *Proxmox) vmPath(vmid string) string {
	return fmt.Sprintf("/nodes/%s/qemu/%s", p.node, vmid)
}

func (p *Proxmox) apiGet(ctx context.Context, path string) (json.RawMessage, error) {
	if p.api != nil {
		return p.api.get(ctx, path)
	}
	out, err := p.pveshGet(ctx, path)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func (p *Proxmox) apiPost(ctx context.Context, path string, params map[string]string) error {
	if p.api != nil {
		_, err := p.api.post(ctx, path, params)
		return err
	}
	args := []string{"create", path}
	for k, v := range params {
		args = append(args, "--"+k, v)
	}
	_, err := p.run.run(ctx, p.pvesh, args...)
	return err
}

func (p *Proxmox) apiPut(ctx context.Context, path string, params map[string]string) error {
	if p.api != nil {
		_, err := p.api.put(ctx, path, params)
		return err
	}
	args := []string{"set", path}
	for k, v := range params {
		args = append(args, "--"+k, v)
	}
	_, err := p.run.run(ctx, p.pvesh, args...)
	return err
}

func (p *Proxmox) apiDelete(ctx context.Context, path string) error {
	if p.api != nil {
		return p.api.delete(ctx, path)
	}
	_, err := p.run.run(ctx, p.pvesh, "delete", path)
	return err
}

func (p *Proxmox) pveshGet(ctx context.Context, path string) (string, error) {
	return p.run.run(ctx, p.pvesh, "get", path, "--output-format", "json")
}

func (p *Proxmox) nextVMID(ctx context.Context) (string, error) {
	if p.api != nil {
		raw, err := p.api.get(ctx, "/cluster/nextid")
		if err != nil {
			return "", fmt.Errorf("compute/proxmox: next vmid: %w", err)
		}
		var id interface{}
		if err := json.Unmarshal(raw, &id); err == nil {
			return fmt.Sprintf("%v", id), nil
		}
		return strings.TrimSpace(strings.Trim(string(raw), "\"")), nil
	}
	out, err := p.pveshGet(ctx, "/cluster/nextid")
	if err != nil {
		return "", fmt.Errorf("compute/proxmox: next vmid: %w", err)
	}
	return strings.TrimSpace(strings.Trim(out, "\"")), nil
}

func (p *Proxmox) findVMID(ctx context.Context, name string) (string, error) {
	raw, err := p.apiGet(ctx, fmt.Sprintf("/nodes/%s/qemu", p.node))
	if err != nil {
		return "", err
	}
	var vms []struct {
		VMID int    `json:"vmid"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &vms); err != nil {
		return "", err
	}
	for _, vm := range vms {
		if vm.Name == name {
			return fmt.Sprint(vm.VMID), nil
		}
	}
	return "", fmt.Errorf("compute/proxmox: no VM named %q on node %s", name, p.node)
}

func (p *Proxmox) inPool(ctx context.Context, vmid string) bool {
	raw, err := p.apiGet(ctx, "/pools/"+p.pool)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), vmid)
}

var _ drivers.ComputeDriver = (*Proxmox)(nil)

// ===========================================================================
// pveAPI — minimal Proxmox VE REST client (stdlib only, no external deps)
// ===========================================================================

type pveAPI struct {
	baseURL     string
	client      *http.Client
	csrfToken   string
	authCookie  string
	tokenID     string
	tokenSecret string

	mu      sync.Mutex
	authExp time.Time
	user    string
	pass    string
}

func newPVEAPI(baseURL, user, password, tokenID, tokenSecret string, verifyTLS bool) (*pveAPI, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL %q: %w", baseURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("API URL must be http(s), got %q", u.Scheme)
	}
	base := strings.TrimRight(baseURL, "/")

	if tokenID == "" && user == "" {
		return nil, fmt.Errorf("either \"user\"+\"password\" or \"token_id\"+\"token_secret\" is required")
	}

	api := &pveAPI{
		baseURL:     base,
		tokenID:     tokenID,
		tokenSecret: tokenSecret,
		user:        user,
		pass:        password,
		client: &http.Client{
			Timeout: 2 * time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !verifyTLS,
				},
			},
		},
	}
	return api, nil
}

func (a *pveAPI) authenticate(ctx context.Context) error {
	if a.tokenID != "" {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if time.Now().Before(a.authExp) && a.authCookie != "" {
		return nil
	}

	form := url.Values{
		"username": {a.user},
		"password": {a.pass},
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		a.baseURL+"/api2/json/access/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("PVE auth request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("PVE auth failed (HTTP %d): %s", resp.StatusCode, truncate(body, 200))
	}

	var result struct {
		Data struct {
			Ticket              string `json:"ticket"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("PVE auth parse: %w", err)
	}
	if result.Data.Ticket == "" {
		return fmt.Errorf("PVE auth: empty ticket (check credentials)")
	}

	a.authCookie = result.Data.Ticket
	a.csrfToken = result.Data.CSRFPreventionToken
	a.authExp = time.Now().Add(90 * time.Minute)
	return nil
}

func (a *pveAPI) setAuth(req *http.Request) {
	if a.tokenID != "" {
		req.Header.Set("Authorization", "PVEAPIToken="+a.tokenID+"="+a.tokenSecret)
		return
	}
	req.AddCookie(&http.Cookie{Name: "PVEAuthCookie", Value: a.authCookie})
	if req.Method != "GET" {
		req.Header.Set("CSRFPreventionToken", a.csrfToken)
	}
}

func (a *pveAPI) do(ctx context.Context, method, path string, form url.Values) (json.RawMessage, error) {
	if err := a.authenticate(ctx); err != nil {
		return nil, err
	}

	apiPath := a.baseURL + "/api2/json" + path

	var bodyReader io.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, method, apiPath, bodyReader)
	if err != nil {
		return nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	a.setAuth(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PVE %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("PVE %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(body, 300))
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return body, nil
	}
	return envelope.Data, nil
}

func (a *pveAPI) get(ctx context.Context, path string) (json.RawMessage, error) {
	return a.do(ctx, "GET", path, nil)
}

func (a *pveAPI) post(ctx context.Context, path string, params map[string]string) (json.RawMessage, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	return a.do(ctx, "POST", path, form)
}

func (a *pveAPI) put(ctx context.Context, path string, params map[string]string) (json.RawMessage, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	return a.do(ctx, "PUT", path, form)
}

func (a *pveAPI) delete(ctx context.Context, path string) error {
	_, err := a.do(ctx, "DELETE", path, nil)
	return err
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
