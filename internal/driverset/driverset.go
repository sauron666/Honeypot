// Package driverset wires the built-in drivers into a registry. It lives apart
// from package drivers so that driver implementations can import the interfaces
// without a cycle; external drivers register the same way through the plugin SDK.
package driverset

import (
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/drivers/compute"
	"github.com/sauron666/Honeypot/internal/drivers/sink"
)

// Default returns a registry with every built-in driver registered.
func Default() *drivers.Registry {
	r := drivers.NewRegistry()

	// Compute: three implementations, so the abstraction is exercised rather
	// than asserted (ADR-008).
	r.Register(compute.InprocInfo(), compute.NewInproc)
	r.Register(compute.PodmanInfo(), compute.NewPodman)
	r.Register(compute.LibvirtInfo(), compute.NewLibvirt)

	// Sinks.
	r.Register(sink.StdoutInfo(), sink.NewStdout)
	r.Register(sink.FileInfo(), sink.NewFile)
	r.Register(sink.WebhookInfo(), sink.NewWebhook)
	r.Register(sink.SyslogInfo(), sink.NewSyslog)

	return r
}
