// Package export renders MIRAGE observations into formats external systems
// consume: STIX 2.1 bundles for threat intelligence platforms (MISP, OpenCTI),
// TheHive alerts, and CSV/TSV IOC lists.
//
// The forge (`internal/forge`) already generates Sigma/Suricata/YARA from a
// single engagement. This package goes wider: it takes a set of engagements
// and builds a STIX 2.1 bundle that tells the story of a campaign, so a threat
// intelligence platform can correlate it with observations from other sources.
package export

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// STIX 2.1 object types used here.
const (
	stixBundle         = "bundle"
	stixIndicator      = "indicator"
	stixObservedData   = "observed-data"
	stixAttackPattern  = "attack-pattern"
	stixRelationship   = "relationship"
	stixIdentity       = "identity"
	stixMalware        = "malware"
	stixInfrastructure = "infrastructure"
)

// Observation is one thing MIRAGE saw that is worth sharing.
type Observation struct {
	SrcIP       string
	Service     string
	Technique   string
	Description string
	Timestamp   time.Time
	IOCType     string // "ipv4-addr", "domain-name", "url", "file:hashes.'SHA-256'"
	IOCValue    string
}

// STIXBundle generates a STIX 2.1 bundle from observations.
func STIXBundle(observations []Observation, tenant, site string) ([]byte, error) {
	identity := stixObject(stixIdentity, "identity--mirage-"+sanitize(tenant), map[string]any{
		"name":           "MIRAGE Deception Platform",
		"identity_class": "system",
		"description":    fmt.Sprintf("Tenant: %s, Site: %s", tenant, site),
	})

	var objects []map[string]any
	objects = append(objects, identity)

	for i, obs := range observations {
		id := fmt.Sprintf("indicator--mirage-%s-%d", sanitize(tenant), i)

		pattern := stixPattern(obs.IOCType, obs.IOCValue)
		if pattern == "" {
			continue
		}

		indicator := stixObject(stixIndicator, id, map[string]any{
			"name":            fmt.Sprintf("MIRAGE: %s from %s", obs.Service, obs.SrcIP),
			"description":     obs.Description,
			"pattern":         pattern,
			"pattern_type":    "stix",
			"valid_from":      obs.Timestamp.UTC().Format(time.RFC3339),
			"indicator_types": []string{"malicious-activity"},
			"created_by_ref":  identity["id"],
		})
		objects = append(objects, indicator)

		if obs.Technique != "" {
			apID := "attack-pattern--" + sanitize(obs.Technique)
			ap := stixObject(stixAttackPattern, apID, map[string]any{
				"name": obs.Technique,
				"external_references": []map[string]any{
					{"source_name": "mitre-attack", "external_id": obs.Technique,
						"url": "https://attack.mitre.org/techniques/" + strings.Replace(obs.Technique, ".", "/", 1)},
				},
			})
			objects = append(objects, ap)

			rel := stixObject(stixRelationship,
				fmt.Sprintf("relationship--mirage-%d-ap", i), map[string]any{
					"relationship_type": "indicates",
					"source_ref":        id,
					"target_ref":        apID,
				})
			objects = append(objects, rel)
		}
	}

	bundle := map[string]any{
		"type":    stixBundle,
		"id":      "bundle--mirage-" + sanitize(tenant) + "-" + fmt.Sprint(time.Now().Unix()),
		"objects": objects,
	}
	return json.MarshalIndent(bundle, "", "  ")
}

// TheHiveAlert generates a TheHive-compatible alert JSON.
func TheHiveAlert(title, description, srcIP, service string, severity int, techniques []string) ([]byte, error) {
	alert := map[string]any{
		"title":       title,
		"description": description,
		"type":        "mirage-deception",
		"source":      "MIRAGE",
		"sourceRef":   fmt.Sprintf("mirage-%s-%d", srcIP, time.Now().Unix()),
		"severity":    severity,
		"tags":        append([]string{"deception", "mirage", service}, techniques...),
		"artifacts": []map[string]any{
			{"dataType": "ip", "data": srcIP, "message": "Source address of the attacker"},
		},
	}
	return json.MarshalIndent(alert, "", "  ")
}

// IOCList generates a simple TSV list of indicators.
func IOCList(observations []Observation) string {
	var b strings.Builder
	b.WriteString("type\tvalue\tservice\ttechnique\ttimestamp\n")
	// Deduplicate on type+value: the same address or URL is seen many times in
	// one intrusion, and a feed that repeats each IOC is noise a TIP has to
	// clean up. The first sighting's context is kept.
	seen := map[string]bool{}
	for _, obs := range observations {
		if obs.IOCValue == "" {
			continue
		}
		key := obs.IOCType + "\x00" + obs.IOCValue
		if seen[key] {
			continue
		}
		seen[key] = true
		b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n",
			obs.IOCType, obs.IOCValue, obs.Service, obs.Technique,
			obs.Timestamp.UTC().Format(time.RFC3339)))
	}
	return b.String()
}

func stixObject(typ, id string, fields map[string]any) map[string]any {
	obj := map[string]any{
		"type":         typ,
		"id":           id,
		"spec_version": "2.1",
		"created":      time.Now().UTC().Format(time.RFC3339),
		"modified":     time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range fields {
		obj[k] = v
	}
	return obj
}

func stixPattern(iocType, iocValue string) string {
	if iocValue == "" {
		return ""
	}
	switch iocType {
	case "ipv4-addr":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", iocValue)
	case "domain-name":
		return fmt.Sprintf("[domain-name:value = '%s']", iocValue)
	case "url":
		return fmt.Sprintf("[url:value = '%s']", iocValue)
	case "file:hashes.'SHA-256'":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", iocValue)
	default:
		return fmt.Sprintf("[%s:value = '%s']", iocType, iocValue)
	}
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
