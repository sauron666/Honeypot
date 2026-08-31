package wireless

import (
	"strings"
	"testing"
)

func TestDefaultHoneyDevicesCoverTheCommonBaits(t *testing.T) {
	devs := DefaultHoneyDevices()
	kinds := map[string]bool{}
	for _, d := range devs {
		kinds[d.Kind] = true
		if d.ServiceType == "" || d.Host == "" || d.Port == 0 {
			t.Errorf("device %q is under-specified: %+v", d.Instance, d)
		}
	}
	for _, want := range []string{"printer", "cast", "airplay"} {
		if !kinds[want] {
			t.Errorf("expected a honey %s device", want)
		}
	}
}

func TestDetectorFlagsBrowsingForHoneyDevices(t *testing.T) {
	d := NewDetector(DefaultHoneyDevices())

	// A device browsing for Chromecast targets — classic BYOD recon.
	if _, hit := d.Match("_googlecast._tcp.local"); !hit {
		t.Fatal("a browse for _googlecast._tcp should be flagged")
	}
	// AirPlay discovery.
	if _, hit := d.Match("_airplay._tcp.local."); !hit {
		t.Fatal("a browse for _airplay._tcp should be flagged")
	}
	// A direct hostname lookup for the honey printer.
	if _, hit := d.Match("reception-printer.local"); !hit {
		t.Fatal("a lookup of the honey printer host should be flagged")
	}
}

func TestDetectorIgnoresUnrelatedQueries(t *testing.T) {
	d := NewDetector(DefaultHoneyDevices())
	for _, q := range []string{"_workstation._tcp.local", "real-server.local", "example.com", ""} {
		if name, hit := d.Match(q); hit {
			t.Errorf("query %q should not match a honey device (matched %q)", q, name)
		}
	}
}

func TestLiveAdvertisingIsHonestAboutScope(t *testing.T) {
	note := LiveAdvertising()
	// It must state the RF boundary plainly (honesty invariant).
	if !strings.Contains(note, "RF hardware") {
		t.Error("the scope note must state that SSID/BLE need RF hardware")
	}
}
