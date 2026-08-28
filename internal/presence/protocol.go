// Package presence implements overlay mode: decoys that appear in a network
// segment without anything being deployed into it.
//
// The problem it solves is organisational, not technical. Deception normally
// requires new VLANs, firewall rules and switch changes -- a network project,
// weeks of approvals, and a deployment that never happens. A Presence Agent
// claims unused addresses in the segment it sits in and tunnels what arrives to
// the decoys, which stay in the isolated zone where they belong.
//
// Containment (ADR-009, docs/04 §4a) shapes the protocol:
//
//   - the tunnel is opened by the agent outward and never the other way, so a
//     compromised decoy has no path into the segment;
//   - only services the hub has declared for that agent are carried;
//   - the agent forwards bytes and nothing else -- it never executes anything
//     a decoy sends, and holds no credentials beyond its own token;
//   - either side closing the tunnel takes every stream down with it.
package presence

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types.
const (
	FrameHello  = 1 // agent -> hub: who I am and what I carry
	FrameAccept = 2 // hub -> agent: accepted, with the services it may forward
	FrameReject = 3 // hub -> agent: refused, with a reason
	FrameOpen   = 4 // agent -> hub: a new inbound connection
	FrameData   = 5 // either way: stream payload
	FrameClose  = 6 // either way: stream finished
	FramePing   = 7 // keepalive, either way
	FramePong   = 8
)

// Limits. A tunnel carries attacker-controlled traffic, so every length is
// bounded and every bound is enforced on read.
const (
	MaxFrameSize    = 64 * 1024
	MaxStreams      = 512
	MaxServices     = 64
	ProtocolVersion = 1
)

var (
	ErrFrameTooLarge  = errors.New("presence: frame exceeds the maximum size")
	ErrBadFrame       = errors.New("presence: malformed frame")
	ErrTooManyStreams = errors.New("presence: too many concurrent streams")
)

// Frame is one message on the tunnel.
//
// Wire format: type (1), stream id (4, big endian), payload length (4), payload.
// Deliberately trivial: this carries hostile traffic, and a parser with corners
// is a parser with bugs.
type Frame struct {
	Type    byte
	Stream  uint32
	Payload []byte
}

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	hdr := make([]byte, 9)
	hdr[0] = f.Type
	binary.BigEndian.PutUint32(hdr[1:5], f.Stream)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(f.Payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(f.Payload) == 0 {
		return nil
	}
	_, err := w.Write(f.Payload)
	return err
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, length)
	}
	f := Frame{Type: hdr[0], Stream: binary.BigEndian.Uint32(hdr[1:5])}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// Hello is the agent's introduction.
type Hello struct {
	Version   int      `json:"version"`
	AgentID   string   `json:"agent_id"`
	Token     string   `json:"token"`
	Addresses []string `json:"addresses"`
	Services  []string `json:"services"`
}

// Accept is the hub's answer.
type Accept struct {
	// Services the agent is permitted to forward. Anything else it sends is
	// dropped, so a compromised agent cannot reach services it was never
	// configured for.
	Services  []string `json:"services"`
	DecoyID   string   `json:"decoy_id"`
	Persona   string   `json:"persona"`
	KeepAlive int      `json:"keepalive_seconds"`
}

// Reject explains a refusal.
type Reject struct {
	Reason string `json:"reason"`
}

// Open describes a new inbound connection the agent accepted.
type Open struct {
	Service string `json:"service"`
	// Source is the attacker's real address. Without it every session in a
	// segment would be attributed to the agent, merging unrelated attackers
	// into one engagement.
	Source string `json:"source"`
	// Local is the claimed address the connection arrived on, which is what
	// the attacker believes they are talking to.
	Local string `json:"local"`
}
