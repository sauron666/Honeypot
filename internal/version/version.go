// Package version carries build metadata, stamped by the linker.
package version

import "fmt"

var (
	// Version is the release version, set at build time.
	Version = "0.1.0-dev"
	// Commit is the git revision, set at build time.
	Commit = "none"
	// BuildDate is the UTC build timestamp, set at build time.
	BuildDate = "unknown"
)

// Product is the name reported in every event's metadata.
const Product = "MIRAGE"

// Vendor is the vendor name reported in every event's metadata.
const Vendor = "MIRAGE Deception"

// String renders a one-line version banner.
func String() string {
	return fmt.Sprintf("%s %s (commit %s, built %s)", Product, Version, Commit, BuildDate)
}
