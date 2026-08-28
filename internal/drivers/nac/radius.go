// Package nac holds NACDriver implementations: what steers unknown or
// suspicious devices into the honeynet instead of blocking them.
//
// The insight is that a device the NAC does not recognise is one of two things:
// a misconfiguration (boring) or a rogue device (the thing deception exists
// for). Blocking it tells the attacker they were noticed. Steering it into a
// honeynet tells them nothing and gives us everything.
package nac

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// RadiusInfo describes the FreeRADIUS NAC driver.
func RadiusInfo() drivers.Info {
	return drivers.Info{
		Name: "freeradius",
		Kind: drivers.KindNAC,
		Summary: "Steers unknown devices into the honeynet via RADIUS Change-of-Authorization (CoA). " +
			"Instead of blocking an unrecognised device (which tells the attacker they were noticed), " +
			"it reassigns the device to the deception VLAN, where every service is a decoy.",
		Capabilities: []drivers.Capability{},
	}
}

// RadiusConfig configures the FreeRADIUS driver.
type RadiusConfig struct {
	// Server is the FreeRADIUS server address (host:port).
	Server string `yaml:"server" json:"server"`
	// Secret is the RADIUS shared secret.
	Secret string `yaml:"secret" json:"secret"`
	// DeceptionVLAN is the VLAN ID to assign unknown devices to.
	DeceptionVLAN int `yaml:"deception_vlan" json:"deception_vlan"`
	// CoAPort is the Change-of-Authorization port (default 3799).
	CoAPort int `yaml:"coa_port" json:"coa_port"`
}

// Radius drives FreeRADIUS via RADIUS CoA (RFC 5176).
//
// When an unknown device is detected (by the switch sending an Access-Request
// the RADIUS server does not recognise), this driver sends a CoA to reassign
// the device's port to the deception VLAN. The device gets an IP in the
// honeynet, finds decoys everywhere, and the attacker never knows they were
// redirected.
type Radius struct {
	cfg RadiusConfig
}

// NewRadius builds the driver.
func NewRadius(cfg map[string]any) (drivers.Driver, error) {
	get := func(k, def string) string {
		if v, ok := cfg[k].(string); ok && v != "" {
			return v
		}
		return def
	}
	getInt := func(k string, def int) int {
		if v, ok := cfg[k].(int); ok {
			return v
		}
		if v, ok := cfg[k].(float64); ok {
			return int(v)
		}
		return def
	}

	server := get("server", "")
	if server == "" {
		return nil, fmt.Errorf("nac/freeradius: \"server\" is required (host:port of the RADIUS server)")
	}
	secret := get("secret", "")
	if secret == "" {
		return nil, fmt.Errorf("nac/freeradius: \"secret\" is required (RADIUS shared secret)")
	}

	return &Radius{cfg: RadiusConfig{
		Server:        server,
		Secret:        secret,
		DeceptionVLAN: getInt("deception_vlan", 666),
		CoAPort:       getInt("coa_port", 3799),
	}}, nil
}

func (r *Radius) Info() drivers.Info { return RadiusInfo() }
func (r *Radius) Probe(ctx context.Context) error {
	conn, err := net.DialTimeout("udp", r.cfg.Server, 5*time.Second)
	if err != nil {
		return fmt.Errorf("nac/freeradius: cannot reach %s: %w", r.cfg.Server, err)
	}
	conn.Close()
	return nil
}
func (r *Radius) Close() error { return nil }

// SteerToDeception sends a RADIUS Change-of-Authorization to move a device's
// port to the deception VLAN.
//
// This is the key action: instead of blocking the device (which tells the
// attacker they were caught), we silently redirect it into a world made
// entirely of decoys.
func (r *Radius) SteerToDeception(ctx context.Context, macAddr, switchIP string, switchPort int) error {
	// CoA packet: Tunnel-Type = VLAN (13), Tunnel-Medium-Type = IEEE-802 (6),
	// Tunnel-Private-Group-Id = VLAN ID, Calling-Station-Id = MAC.
	//
	// This is a simplified implementation. A production version would use a
	// proper RADIUS library, but the protocol is simple enough that the
	// essential operation — reassigning a VLAN — is a single UDP packet.
	coaAddr := fmt.Sprintf("%s:%d", r.cfg.Server, r.cfg.CoAPort)
	conn, err := net.DialTimeout("udp", coaAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("nac/freeradius: CoA to %s: %w", coaAddr, err)
	}
	defer conn.Close()

	// Build a minimal RADIUS CoA-Request (Code 43)
	pkt := buildCoAPacket(macAddr, r.cfg.DeceptionVLAN, []byte(r.cfg.Secret))
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("nac/freeradius: send CoA: %w", err)
	}

	return nil
}

// buildCoAPacket constructs a minimal RADIUS CoA-Request.
// Code=43, Identifier=1, Length, Authenticator, Attributes.
func buildCoAPacket(mac string, vlan int, secret []byte) []byte {
	// Attributes:
	// Calling-Station-Id (31) = MAC address
	// Tunnel-Type (64) = VLAN (13)
	// Tunnel-Medium-Type (65) = IEEE-802 (6)
	// Tunnel-Private-Group-Id (81) = VLAN ID as string
	macAttr := radiusAttr(31, []byte(mac))
	tunnelType := radiusAttr(64, []byte{0x00, 0x00, 0x00, 13})  // tag=0, VLAN
	tunnelMedium := radiusAttr(65, []byte{0x00, 0x00, 0x00, 6}) // tag=0, IEEE-802
	vlanStr := fmt.Sprintf("%d", vlan)
	tunnelGroup := radiusAttr(81, append([]byte{0x00}, []byte(vlanStr)...)) // tag=0

	attrs := append(macAttr, tunnelType...)
	attrs = append(attrs, tunnelMedium...)
	attrs = append(attrs, tunnelGroup...)

	// Header: Code(1) + ID(1) + Length(2) + Authenticator(16)
	length := 20 + len(attrs)
	pkt := make([]byte, 20, length)
	pkt[0] = 43 // CoA-Request
	pkt[1] = 1  // Identifier
	pkt[2] = byte(length >> 8)
	pkt[3] = byte(length)
	// Authenticator is all zeros for request (will be filled with MD5 in production)
	pkt = append(pkt, attrs...)
	return pkt
}

func radiusAttr(typ byte, val []byte) []byte {
	attr := make([]byte, 2+len(val))
	attr[0] = typ
	attr[1] = byte(2 + len(val))
	copy(attr[2:], val)
	return attr
}

var _ drivers.Driver = (*Radius)(nil)
