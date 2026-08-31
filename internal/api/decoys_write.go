package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/sauron666/Honeypot/internal/honeyd"
)

// This file gives the operator console form-driven add and remove of decoys,
// the counterpart of pasting a YAML manifest under Configuration. The apply
// path is exactly the same one (s.deps.Apply → Farm.Reconcile): the whole
// listener set is validated atomically and runtime options (host keys, token
// lookup) are reinjected, so a decoy built from the form is indistinguishable
// from one built from a manifest. The form is a convenience over the manifest,
// never a second, weaker path into the farm.

// decoySpec is one decoy as the console composes it: an identity, the
// addresses it occupies and the ports it answers. It mirrors
// config.DecoyConfig but is the JSON the builder POSTs.
type decoySpec struct {
	ID        string   `json:"id"`
	Persona   string   `json:"persona"`
	Addresses []string `json:"addresses"`
	Services  []struct {
		Service  string `json:"service"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"services"`
}

// serviceCatalog lists what a decoy can be built from: the registered protocols
// and the known personas. The builder form populates its dropdowns from this so
// it can never offer a service or persona the farm would reject on apply.
func (s *Server) serviceCatalog(w http.ResponseWriter, r *http.Request) {
	svcs := honeyd.ServiceNames()
	sort.Strings(svcs)
	personas := honeyd.PersonaNames()
	sort.Strings(personas)
	writeJSON(w, http.StatusOK, map[string]any{
		"services": svcs,
		"personas": personas,
	})
}

// addDecoy composes a decoy from the form and reconciles the running farm with
// it: the current set, minus any decoy with the same id, plus this one. Adding
// a decoy whose id already exists therefore edits it in place.
func (s *Server) addDecoy(w http.ResponseWriter, r *http.Request) {
	if s.deps.Farm == nil || s.deps.Apply == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "this deployment does not support applying configuration"})
		return
	}
	var spec decoySpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid decoy JSON: " + err.Error()})
		return
	}
	spec.ID = strings.TrimSpace(spec.ID)
	if spec.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decoy id is required"})
		return
	}
	if !personaExists(spec.Persona) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown persona " + spec.Persona})
		return
	}
	if len(spec.Services) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a decoy needs at least one service"})
		return
	}
	newListeners, err := spec.listeners(serviceNameSet())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Keep every listener that is not this decoy, then append the new ones.
	// Replacing by id lets "add" double as "edit".
	var merged []honeyd.ListenerConfig
	for _, l := range s.deps.Farm.Listeners() {
		if l.DecoyID != spec.ID {
			merged = append(merged, l)
		}
	}
	merged = append(merged, newListeners...)
	added, removed, err := s.deps.Apply(merged)
	if err != nil {
		// Reconcile validates the whole set before touching anything, so a
		// failure here means the running farm is unchanged.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "applied": false})
		return
	}
	s.deps.Log.Info("decoy applied from console",
		"decoy", spec.ID, "added", len(added), "removed", len(removed))
	writeJSON(w, http.StatusOK, map[string]any{
		"applied": true, "decoy": spec.ID, "added": added, "removed": removed,
	})
}

// removeDecoy drops every listener a decoy owns and reconciles. An emulated
// listener is not evidence, so removing one is safe -- unlike a full-OS VM
// decoy, which is never recycled once it has been touched.
func (s *Server) removeDecoy(w http.ResponseWriter, r *http.Request) {
	if s.deps.Farm == nil || s.deps.Apply == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "this deployment does not support applying configuration"})
		return
	}
	id := r.PathValue("id")
	var kept []honeyd.ListenerConfig
	found := false
	for _, l := range s.deps.Farm.Listeners() {
		if l.DecoyID == id {
			found = true
			continue
		}
		kept = append(kept, l)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no decoy " + id})
		return
	}
	added, removed, err := s.deps.Apply(kept)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "applied": false})
		return
	}
	s.deps.Log.Info("decoy removed from console", "decoy", id, "removed", len(removed))
	writeJSON(w, http.StatusOK, map[string]any{
		"applied": true, "decoy": id, "added": added, "removed": removed,
	})
}

func serviceNameSet() map[string]bool {
	set := map[string]bool{}
	for _, n := range honeyd.ServiceNames() {
		set[n] = true
	}
	return set
}

// listeners expands a decoy spec into the flat listener set the farm binds: one
// listener per address per service. An empty address list means the farm's
// default bind, matching config.DecoyConfig semantics.
func (spec decoySpec) listeners(known map[string]bool) ([]honeyd.ListenerConfig, error) {
	addrs := spec.Addresses
	if len(addrs) == 0 {
		addrs = []string{""}
	}
	var out []honeyd.ListenerConfig
	for _, svc := range spec.Services {
		name := strings.TrimSpace(svc.Service)
		if !known[name] {
			return nil, fmt.Errorf("unknown service %q", name)
		}
		if svc.Port <= 0 || svc.Port > 65535 {
			return nil, fmt.Errorf("service %q: port %d out of range", name, svc.Port)
		}
		proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
		if proto != "" && proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("service %q: protocol must be tcp, udp or empty", name)
		}
		for _, a := range addrs {
			out = append(out, honeyd.ListenerConfig{
				Service:  name,
				Address:  strings.TrimSpace(a),
				Port:     svc.Port,
				Persona:  spec.Persona,
				DecoyID:  spec.ID,
				Protocol: proto,
			})
		}
	}
	return out, nil
}
