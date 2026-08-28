// Package driverset wires the built-in drivers into a registry. It lives apart
// from package drivers so that driver implementations can import the interfaces
// without a cycle; external drivers register the same way through the plugin SDK.
package driverset

import (
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/drivers/compute"
	"github.com/sauron666/Honeypot/internal/drivers/fabric"
	"github.com/sauron666/Honeypot/internal/drivers/nac"
	"github.com/sauron666/Honeypot/internal/drivers/observer"
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
	r.Register(compute.ProxmoxInfo(), compute.NewProxmox)

	// Fabric: two drivers that answer different questions. nftables reads and
	// writes the intent; probe tests what a packet actually reaches. A
	// deployment where they disagree is the one that turns a honeypot into a
	// beachhead, and only running both finds it.
	r.Register(fabric.NftablesInfo(), fabric.NewNftables)
	r.Register(fabric.ProbeInfo(), fabric.NewProbe)

	// Observer: two implementations so the category is real. drakvuf is the
	// agentless VMI observer (experimental until validated on Xen hardware);
	// none is the honest choice for a deployment with no hypervisor.
	r.Register(observer.NoneInfo(), observer.NewNone)
	r.Register(observer.DrakvufInfo(), observer.NewDrakvuf)

	// NAC: steering unknown devices into the honeynet.
	r.Register(nac.RadiusInfo(), nac.NewRadius)

	// Sinks.
	r.Register(sink.StdoutInfo(), sink.NewStdout)
	r.Register(sink.FileInfo(), sink.NewFile)
	r.Register(sink.WebhookInfo(), sink.NewWebhook)
	r.Register(sink.SyslogInfo(), sink.NewSyslog)
	r.Register(sink.ElasticInfo(), sink.NewElastic)
	r.Register(sink.SplunkInfo(), sink.NewSplunk)

	return r
}
