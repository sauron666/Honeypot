// Package wireless is BYOD / rogue-device deception (idea 20).
//
// Scope, stated honestly: the RF surface — a honey SSID for karma/rogue-AP
// bait, honey BLE beacons — needs a radio and is out of a pure-Go product's
// reach. What IS reachable, and catches the same class of intruder, is the
// IP-layer discovery surface every phone and laptop lights up the moment it
// joins a network: mDNS / DNS-SD (Bonjour), SSDP (UPnP), LLMNR. This package
// defines honey devices to advertise there (a printer, a Chromecast, an AirPlay
// target, a NAS) and a detector that flags a source browsing for them.
//
// On a corporate LAN nothing legitimate goes looking to cast to a TV or print
// to an unknown printer from an unmanaged device — so a query for a honey
// device, or a connection to one, is a rogue/BYOD signal. Advertising these
// over live mDNS is a responder integration (a hook point, noted below); the
// descriptors and the recon detector are here and tested.
package wireless

import (
	"sort"
	"strings"
)

// HoneyDevice is a fake network-discoverable device.
type HoneyDevice struct {
	// Instance is the human name, e.g. "Reception Printer".
	Instance string `json:"instance"`
	// ServiceType is the DNS-SD service type, e.g. "_ipp._tcp".
	ServiceType string `json:"service_type"`
	// Host is the mDNS hostname, e.g. "reception-printer.local".
	Host string `json:"host"`
	Port int    `json:"port"`
	// TXT are the DNS-SD TXT key=value records that make it look real.
	TXT []string `json:"txt,omitempty"`
	// Kind categorises it for the operator: printer, cast, airplay, nas.
	Kind string `json:"kind"`
}

// DefaultHoneyDevices returns a plausible set of discoverable bait devices.
func DefaultHoneyDevices() []HoneyDevice {
	return []HoneyDevice{
		{Instance: "Reception Printer", ServiceType: "_ipp._tcp", Host: "reception-printer.local",
			Port: 631, Kind: "printer", TXT: []string{"ty=HP LaserJet MFP", "rp=ipp/print", "note=Front desk"}},
		{Instance: "Boardroom TV", ServiceType: "_googlecast._tcp", Host: "boardroom-tv.local",
			Port: 8009, Kind: "cast", TXT: []string{"md=Chromecast", "fn=Boardroom TV"}},
		{Instance: "Exec AirPlay", ServiceType: "_airplay._tcp", Host: "exec-airplay.local",
			Port: 7000, Kind: "airplay", TXT: []string{"model=AppleTV", "deviceid=aa:bb:cc:dd:ee:ff"}},
		{Instance: "Backup NAS", ServiceType: "_smb._tcp", Host: "backup-nas.local",
			Port: 445, Kind: "nas", TXT: []string{"model=Synology"}},
	}
}

// BrowseNames returns the DNS-SD browse names a source would query to discover
// each honey device, e.g. "_googlecast._tcp.local". A query for one of these
// from an unmanaged source is the recon signal.
func BrowseNames(devices []HoneyDevice) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range devices {
		for _, n := range []string{
			d.ServiceType + ".local",
			d.Instance + "." + d.ServiceType + ".local",
			d.Host,
		} {
			key := strings.ToLower(n)
			if !seen[key] {
				seen[key] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Detector flags discovery traffic aimed at a honey device. It matches an mDNS
// query name, an SSDP search target, or an LLMNR name against the honey set.
type Detector struct {
	names []string // lowercased browse names + hostnames
}

// NewDetector builds a detector for the given honey devices.
func NewDetector(devices []HoneyDevice) *Detector {
	names := BrowseNames(devices)
	low := make([]string, len(names))
	for i, n := range names {
		low[i] = strings.ToLower(n)
	}
	return &Detector{names: low}
}

// Match reports whether a discovery query (mDNS/SSDP/LLMNR name) targets a honey
// device. It is a substring match so it copes with the trailing dot, the query
// class suffix, and instance-vs-service forms.
func (d *Detector) Match(queryName string) (string, bool) {
	q := strings.ToLower(strings.TrimSpace(queryName))
	if q == "" {
		return "", false
	}
	for _, n := range d.names {
		if strings.Contains(q, n) || strings.Contains(n, q) && len(q) > 4 {
			return n, true
		}
	}
	return "", false
}

// LiveAdvertising documents, in one place, the honest boundary: turning these
// descriptors into live mDNS/SSDP responses is a responder integration (bind
// UDP 5353 multicast for mDNS, 1900 for SSDP) and the RF baits (SSID/BLE) need a
// radio. This function returns that note so the CLI/GUI can show it plainly.
func LiveAdvertising() string {
	return "advertising over live mDNS (UDP 5353) / SSDP (UDP 1900) is a responder " +
		"integration; honey SSID, BLE beacons and karma-attack bait need RF hardware " +
		"and are out of scope for the software product. The descriptors and the recon " +
		"detector above work today against discovery traffic you can already see."
}
