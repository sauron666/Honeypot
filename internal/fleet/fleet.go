// Package fleet manages the rotation of decoy identities over time.
//
// A decoy that looks the same forever can be mapped: an attacker who
// fingerprints it once knows it next time. Fleet rotation cycles identities
// on a schedule — new hostnames, new IPs where the address pool allows it,
// new SSH host keys, new planted credentials — so the estate looks different
// every time. The schedule is deliberately irregular (seeded jitter) to avoid
// a pattern that would itself be a fingerprint.
//
// Rotation is non-disruptive: it uses the existing plan/apply reconciliation
// (Deception-as-Code), so a rotation is just a manifest change. If an attacker
// is inside a decoy at the moment of rotation, the rotation is deferred until
// the engagement closes — resetting a host mid-session is the loudest tell
// a deception platform can produce.
package fleet

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// RotationPlan describes when and how to rotate.
type RotationPlan struct {
	// Interval is the base period between rotations. Actual timing is jittered
	// by ±30% from the seed, so no two deployments rotate on the same schedule.
	Interval time.Duration `yaml:"interval" json:"interval"`
	// Seed makes the jitter deterministic per deployment.
	Seed string `yaml:"seed" json:"seed"`
	// Exclude lists decoy IDs that should never be rotated (e.g. a burned
	// decoy kept as evidence, or a decoy an analyst is examining).
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

// DecoyIdentity is one decoy's rotatable attributes.
type DecoyIdentity struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Seed     string `json:"seed"` // the per-deployment seed for this generation
}

// Schedule computes which decoys should be rotated at the given time, and
// what their new identities should be. It is a pure function: given the same
// plan and time, it always returns the same answer.
func Schedule(plan RotationPlan, decoyIDs []string, now time.Time) []DecoyIdentity {
	excluded := map[string]bool{}
	for _, id := range plan.Exclude {
		excluded[id] = true
	}

	rng := seedRNG(plan.Seed, now.Truncate(plan.Interval))
	jitterRange := int64(float64(plan.Interval) * 0.3)

	var due []DecoyIdentity
	for _, id := range decoyIDs {
		if excluded[id] {
			continue
		}
		// Each decoy has its own jittered rotation window, derived from the seed
		// and the decoy ID. This spreads rotations across the interval rather
		// than cycling everything at once (which itself would be visible).
		jitter := time.Duration(rng.Int63n(jitterRange*2) - jitterRange)
		nextRotation := now.Truncate(plan.Interval).Add(jitter)
		if now.After(nextRotation) {
			gen := generation(plan.Seed, id, now, plan.Interval)
			due = append(due, DecoyIdentity{
				ID:       id,
				Hostname: newHostname(plan.Seed, id, gen),
				Seed:     fmt.Sprintf("%s|gen-%d", plan.Seed, gen),
			})
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].ID < due[j].ID })
	return due
}

// generation computes which generation of identity a decoy is in at a given time.
func generation(seed, decoyID string, now time.Time, interval time.Duration) int {
	elapsed := now.Sub(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	return int(elapsed / interval)
}

// newHostname generates a plausible hostname for this generation.
func newHostname(seed, decoyID string, gen int) string {
	rng := seedRNG(seed+"|"+decoyID, time.Unix(int64(gen), 0))
	prefixes := []string{"srv", "app", "web", "db", "dc", "fs", "nas", "bk", "mon", "jump"}
	suffixes := []string{"01", "02", "03", "04", "05", "a", "b", "prod", "stg"}
	prefix := prefixes[rng.Intn(len(prefixes))]
	suffix := suffixes[rng.Intn(len(suffixes))]
	return strings.ToUpper(fmt.Sprintf("%s-%s-%02d", prefix, suffix, rng.Intn(99)+1))
}

func seedRNG(seed string, t time.Time) *rand.Rand {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", seed, t.Unix())))
	return rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(sum[:8]))))
}

// Deferred reports whether a rotation should be deferred because an engagement
// is active on the decoy. This is not a decision the fleet package makes — it
// asks the engagement tracker and respects the answer.
func Deferred(activeDecoys map[string]bool, id string) bool {
	return activeDecoys[id]
}
