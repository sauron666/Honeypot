package honeyd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("snmp", newSNMP) }

// snmpSvc answers SNMP v1/v2c over UDP.
//
// The community string is a credential, and it is sent in the clear: "public",
// "private" and whatever the attacker guessed next are all worth recording.
// The server enforces the anti-amplification rules for us (see PacketService),
// which is why the answers here are deliberately terse.
type snmpSvc struct {
	p       *Persona
	sysDesc string
}

func newSNMP(p *Persona, opts map[string]any) (Service, error) {
	s := &snmpSvc{p: p, sysDesc: "Linux " + p.Hostname}
	if v, ok := opts["sys_descr"].(string); ok && v != "" {
		s.sysDesc = v
	}
	return s, nil
}

func (s *snmpSvc) Type() string { return "snmp" }

// Serve exists to satisfy Service; SNMP is answered as datagrams.
func (s *snmpSvc) Serve(context.Context, net.Conn, *Session) error {
	return errors.New("snmp: this is a UDP service")
}

func (s *snmpSvc) ServePacket(_ context.Context, sess *Session, payload []byte) ([]byte, error) {
	msg, err := parseSNMP(payload)
	if err != nil {
		sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityLow).
			WithMessage("malformed SNMP datagram (%d bytes)", len(payload)).
			Set("parse_error", err.Error()))
		return nil, nil
	}

	// The community string is the credential. Recording which ones are tried,
	// and in what order, fingerprints the scanner as much as the attempt.
	sess.AddCredential(Credential{
		Username: "", Secret: msg.community, Method: "snmp-community", Accepted: false,
	})

	sev := event.SeverityMedium
	techniques := []event.Technique{
		{Tactic: "TA0007", Technique: "T1046", Name: "Network Service Discovery"},
	}
	if msg.pduType == snmpSetRequest {
		// A write attempt against network gear is not reconnaissance.
		sev = event.SeverityCritical
		techniques = append(techniques, event.Technique{
			Tactic: "TA0005", Technique: "T1600", Name: "Weaken Encryption / Modify System Image"})
	}

	e := sess.Event(event.ClassDecoyInteraction, 1, sev).
		WithMessage("SNMP %s (v%s) community %q oid %s",
			snmpPDUName(msg.pduType), snmpVersionName(msg.version), msg.community, msg.oid).
		WithAttack(techniques...)
	e.Set("snmp_version", snmpVersionName(msg.version)).
		Set("community", msg.community).
		Set("pdu_type", snmpPDUName(msg.pduType)).
		Set("oid", msg.oid).
		Set("request_bytes", len(payload))
	sess.Emit(e)

	if msg.pduType != snmpGetRequest && msg.pduType != snmpGetNextRequest {
		return nil, nil
	}
	// Answer with a short value for the requested OID. Long answers would be
	// withheld by the amplification guard anyway.
	return buildSNMPResponse(msg, s.shortValue(msg.oid)), nil
}

func (s *snmpSvc) shortValue(oid string) string {
	switch {
	case strings.HasPrefix(oid, "1.3.6.1.2.1.1.5"): // sysName
		return s.p.Hostname
	case strings.HasPrefix(oid, "1.3.6.1.2.1.1.6"): // sysLocation
		return "DC1"
	case strings.HasPrefix(oid, "1.3.6.1.2.1.1.4"): // sysContact
		return "it@" + s.p.Domain
	default:
		return s.p.Hostname
	}
}

// --- minimal BER ------------------------------------------------------------

const (
	snmpGetRequest     = 0xa0
	snmpGetNextRequest = 0xa1
	snmpGetResponse    = 0xa2
	snmpSetRequest     = 0xa3
	snmpGetBulk        = 0xa5
)

type snmpMessage struct {
	version   int
	community string
	pduType   byte
	requestID []byte
	oid       string
	oidRaw    []byte
}

func snmpVersionName(v int) string {
	switch v {
	case 0:
		return "1"
	case 1:
		return "2c"
	case 3:
		return "3"
	default:
		return fmt.Sprint(v)
	}
}

func snmpPDUName(t byte) string {
	switch t {
	case snmpGetRequest:
		return "GetRequest"
	case snmpGetNextRequest:
		return "GetNextRequest"
	case snmpSetRequest:
		return "SetRequest"
	case snmpGetBulk:
		return "GetBulkRequest"
	default:
		return fmt.Sprintf("pdu-0x%02x", t)
	}
}

// parseSNMP walks just enough BER to reach the community string and first OID.
func parseSNMP(b []byte) (*snmpMessage, error) {
	body, err := berExpect(b, 0x30)
	if err != nil {
		return nil, err
	}
	verBytes, rest, err := berRead(body, 0x02)
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	comm, rest, err := berRead(rest, 0x04)
	if err != nil {
		return nil, fmt.Errorf("community: %w", err)
	}
	if len(rest) < 2 {
		return nil, errors.New("truncated after community")
	}
	msg := &snmpMessage{version: berInt(verBytes), community: string(comm), pduType: rest[0]}

	pdu, _, err := berRead(rest, rest[0])
	if err != nil {
		return nil, fmt.Errorf("pdu: %w", err)
	}
	reqID, pduRest, err := berRead(pdu, 0x02)
	if err != nil {
		return nil, fmt.Errorf("request id: %w", err)
	}
	msg.requestID = reqID
	// Skip error-status and error-index.
	if _, pduRest, err = berRead(pduRest, 0x02); err != nil {
		return msg, nil
	}
	if _, pduRest, err = berRead(pduRest, 0x02); err != nil {
		return msg, nil
	}
	varbinds, _, err := berRead(pduRest, 0x30)
	if err != nil {
		return msg, nil
	}
	first, _, err := berRead(varbinds, 0x30)
	if err != nil {
		return msg, nil
	}
	oidRaw, _, err := berRead(first, 0x06)
	if err != nil {
		return msg, nil
	}
	msg.oidRaw = oidRaw
	msg.oid = decodeOID(oidRaw)
	return msg, nil
}

func berExpect(b []byte, tag byte) ([]byte, error) {
	v, _, err := berRead(b, tag)
	return v, err
}

// berRead reads one TLV with the expected tag and returns its value and the
// bytes that follow it.
func berRead(b []byte, tag byte) (value, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errors.New("truncated")
	}
	if b[0] != tag {
		return nil, nil, fmt.Errorf("expected tag 0x%02x, got 0x%02x", tag, b[0])
	}
	length := int(b[1])
	pos := 2
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return nil, nil, errors.New("bad length")
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(b[2+i])
		}
		pos = 2 + n
	}
	if length < 0 || pos+length > len(b) {
		return nil, nil, errors.New("length exceeds buffer")
	}
	return b[pos : pos+length], b[pos+length:], nil
}

func berInt(b []byte) int {
	v := 0
	for _, x := range b {
		v = v<<8 | int(x)
	}
	return v
}

func decodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []string{fmt.Sprint(b[0] / 40), fmt.Sprint(b[0] % 40)}
	var cur uint64
	for _, x := range b[1:] {
		cur = cur<<7 | uint64(x&0x7f)
		if x&0x80 == 0 {
			parts = append(parts, fmt.Sprint(cur))
			cur = 0
		}
	}
	return strings.Join(parts, ".")
}

func berTLV(tag byte, value []byte) []byte {
	out := []byte{tag}
	n := len(value)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

func buildSNMPResponse(msg *snmpMessage, value string) []byte {
	varbind := berTLV(0x30, append(berTLV(0x06, msg.oidRaw), berTLV(0x04, []byte(value))...))
	varbinds := berTLV(0x30, varbind)

	pdu := berTLV(0x02, msg.requestID)
	pdu = append(pdu, berTLV(0x02, []byte{0})...) // error status
	pdu = append(pdu, berTLV(0x02, []byte{0})...) // error index
	pdu = append(pdu, varbinds...)

	body := berTLV(0x02, []byte{byte(msg.version)})
	body = append(body, berTLV(0x04, []byte(msg.community))...)
	body = append(body, berTLV(snmpGetResponse, pdu)...)
	return berTLV(0x30, body)
}
