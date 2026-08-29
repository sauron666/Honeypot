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
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
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
	// CoA goes to the NAS on the CoA port, not to the RADIUS auth port in
	// Server. Server may be "host" or "host:port"; take just the host and pair
	// it with CoAPort. Building "Server:CoAPort" blindly yields "host:1812:3799".
	coaHost := r.cfg.Server
	if h, _, err := net.SplitHostPort(r.cfg.Server); err == nil {
		coaHost = h
	}
	coaAddr := net.JoinHostPort(coaHost, fmt.Sprintf("%d", r.cfg.CoAPort))
	conn, err := net.DialTimeout("udp", coaAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("nac/freeradius: CoA to %s: %w", coaAddr, err)
	}
	defer conn.Close()

	// Build a signed CoA-Request. The Request Authenticator is not optional:
	// RFC 5176 requires it, and FreeRADIUS drops a CoA whose authenticator does
	// not verify -- so a packet with a zero authenticator looks like success to
	// us while the server silently rejects it. That is the worst kind of bug in
	// a security control: it reports that it steered a device it did not.
	id := randByte()
	pkt := buildCoAPacket(id, macAddr, r.cfg.DeceptionVLAN, []byte(r.cfg.Secret))
	requestAuth := append([]byte(nil), pkt[4:20]...)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("nac/freeradius: send CoA: %w", err)
	}

	// Read the reply and act on it. A NAS answers CoA-ACK (44) on success or
	// CoA-NAK (45) on refusal; treating both as success would again mean
	// claiming a steering that did not happen.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return fmt.Errorf("nac/freeradius: no reply to CoA from %s (device not steered): %w", coaAddr, err)
	}
	if n < 20 {
		return fmt.Errorf("nac/freeradius: truncated CoA reply (%d bytes)", n)
	}
	// A reply must be for our request and carry a valid Response Authenticator,
	// or it is a spoof or a secret mismatch -- either way not proof of steering.
	if resp[1] != id {
		return fmt.Errorf("nac/freeradius: CoA reply id %d does not match request %d", resp[1], id)
	}
	want := coaResponseAuthenticator(resp[:n], requestAuth, []byte(r.cfg.Secret))
	if !hmacEqual(resp[4:20], want) {
		return fmt.Errorf("nac/freeradius: CoA reply failed authenticator check; " +
			"the shared secret does not match the NAS")
	}
	switch resp[0] {
	case 44: // CoA-ACK
		return nil
	case 45: // CoA-NAK
		return fmt.Errorf("nac/freeradius: the NAS refused to steer %s (CoA-NAK); "+
			"check that it supports RFC 5176 CoA and the shared secret matches", macAddr)
	default:
		return fmt.Errorf("nac/freeradius: unexpected CoA reply code %d", resp[0])
	}
}

// buildCoAPacket constructs a signed RADIUS CoA-Request (RFC 5176).
//
// Attributes carried:
//
//	Calling-Station-Id (31)      = MAC, identifies the session to reassign
//	Tunnel-Type (64)             = VLAN (13)
//	Tunnel-Medium-Type (65)      = IEEE-802 (6)
//	Tunnel-Private-Group-Id (81) = the deception VLAN id
func buildCoAPacket(id byte, mac string, vlan int, secret []byte) []byte {
	macAttr := radiusAttr(31, []byte(mac))
	tunnelType := radiusAttr(64, []byte{0x00, 0x00, 0x00, 13})  // tag=0, VLAN
	tunnelMedium := radiusAttr(65, []byte{0x00, 0x00, 0x00, 6}) // tag=0, IEEE-802
	vlanStr := fmt.Sprintf("%d", vlan)
	tunnelGroup := radiusAttr(81, append([]byte{0x00}, []byte(vlanStr)...)) // tag=0

	attrs := append(macAttr, tunnelType...)
	attrs = append(attrs, tunnelMedium...)
	attrs = append(attrs, tunnelGroup...)

	length := 20 + len(attrs)
	pkt := make([]byte, 20, length)
	pkt[0] = 43 // CoA-Request
	pkt[1] = id
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
	// The 16 authenticator octets are zero while computing the signature.
	pkt = append(pkt, attrs...)

	// Request Authenticator = MD5(Code+ID+Length+16 zero octets+Attributes+Secret).
	sum := md5.New()
	sum.Write(pkt)
	sum.Write(secret)
	copy(pkt[4:20], sum.Sum(nil))
	return pkt
}

// coaResponseAuthenticator computes what a valid reply's authenticator must be,
// so a caller can reject a spoofed or misconfigured NAS reply:
// MD5(Code+ID+Length+RequestAuthenticator+Attributes+Secret).
func coaResponseAuthenticator(reply, requestAuth, secret []byte) []byte {
	sum := md5.New()
	sum.Write(reply[:4])
	sum.Write(requestAuth)
	if len(reply) > 20 {
		sum.Write(reply[20:])
	}
	sum.Write(secret)
	return sum.Sum(nil)
}

// randByte is used where an unpredictable identifier helps; falls back to time.
func randByte() byte {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return byte(time.Now().UnixNano())
	}
	return b[0]
}

// hmacEqual is a constant-time comparison, so a wrong secret cannot be probed
// by timing the authenticator check.
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func radiusAttr(typ byte, val []byte) []byte {
	attr := make([]byte, 2+len(val))
	attr[0] = typ
	attr[1] = byte(2 + len(val))
	copy(attr[2:], val)
	return attr
}

var _ drivers.Driver = (*Radius)(nil)
