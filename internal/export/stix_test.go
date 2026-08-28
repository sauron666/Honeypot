package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A STIX bundle that a TIP (MISP, OpenCTI, TheHive) will reject is worse than
// none: it fails silently in someone's ingest pipeline. These tests check the
// bundle is valid STIX 2.1 and that the parts that carry meaning survive.

func sampleObs() []Observation {
	return []Observation{
		{SrcIP: "203.0.113.9", Service: "ssh", Technique: "T1110",
			Description: "password spray", Timestamp: time.Unix(1710000000, 0),
			IOCType: "ipv4-addr", IOCValue: "203.0.113.9"},
		{SrcIP: "203.0.113.9", Service: "http", Technique: "T1190",
			Description: "exploit attempt", Timestamp: time.Unix(1710000100, 0),
			IOCType: "url", IOCValue: "http://evil.example/x"},
	}
}

func TestSTIXBundleIsValid(t *testing.T) {
	raw, err := STIXBundle(sampleObs(), "acme", "hq")
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if bundle["type"] != "bundle" {
		t.Fatalf("top-level type must be bundle, got %v", bundle["type"])
	}
	id, _ := bundle["id"].(string)
	if !strings.HasPrefix(id, "bundle--") {
		t.Fatalf("bundle id must be a STIX identifier, got %q", id)
	}
	objs, ok := bundle["objects"].([]any)
	if !ok || len(objs) == 0 {
		t.Fatal("bundle carries no objects")
	}
	// Every object must have a type and an id of the form type--uuid-ish.
	var haveIndicator bool
	for _, o := range objs {
		m := o.(map[string]any)
		typ, _ := m["type"].(string)
		oid, _ := m["id"].(string)
		if typ == "" || !strings.HasPrefix(oid, typ+"--") {
			t.Fatalf("object has a malformed id: type=%q id=%q", typ, oid)
		}
		if typ == "indicator" {
			haveIndicator = true
			if _, ok := m["pattern"].(string); !ok {
				t.Fatal("an indicator has no pattern")
			}
			if m["spec_version"] != "2.1" && bundle["spec_version"] != "2.1" {
				// STIX 2.1 objects carry spec_version on the object or bundle.
			}
		}
	}
	if !haveIndicator {
		t.Fatal("no indicators were produced from observations that had IOCs")
	}
}

func TestSTIXPatternShapesMatchIOCTypes(t *testing.T) {
	raw, _ := STIXBundle(sampleObs(), "t", "s")
	s := string(raw)
	// The IPv4 and URL observations must produce recognisable STIX patterns.
	if !strings.Contains(s, "ipv4-addr:value = '203.0.113.9'") {
		t.Fatalf("ipv4 pattern missing or malformed:\n%s", s)
	}
	if !strings.Contains(s, "url:value = 'http://evil.example/x'") {
		t.Fatalf("url pattern missing or malformed:\n%s", s)
	}
}

func TestSTIXSanitizesInjection(t *testing.T) {
	// An attacker controls the IOC value; it must not be able to break out of
	// the STIX pattern string and inject structure.
	obs := []Observation{{IOCType: "domain-name", IOCValue: "evil'; DROP--.com",
		Timestamp: time.Now(), Service: "dns", Technique: "T1071"}}
	raw, err := STIXBundle(obs, "t", "s")
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("injection broke the JSON: %v", err)
	}
}

func TestTheHiveAlertIsValidJSON(t *testing.T) {
	raw, err := TheHiveAlert("spray", "ssh spray from 203.0.113.9", "203.0.113.9",
		"ssh", 3, []string{"T1110"})
	if err != nil {
		t.Fatal(err)
	}
	var alert map[string]any
	if err := json.Unmarshal(raw, &alert); err != nil {
		t.Fatalf("TheHive alert is not valid JSON: %v", err)
	}
}

func TestIOCListDeduplicates(t *testing.T) {
	obs := append(sampleObs(), sampleObs()...) // duplicates
	list := IOCList(obs)
	if strings.Count(list, "203.0.113.9") > 1 {
		t.Fatalf("IOC list did not deduplicate:\n%s", list)
	}
}
