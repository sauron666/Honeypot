package honeyd

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Kerberos DER, the subset a KDC needs to read an AS-REQ or a TGS-REQ and write
// a reply. It builds on the BER helpers in ber.go rather than pulling in an
// ASN.1 library, for the same reason the LDAP server does: a decoy has to be
// wrong in the ways real software is wrong, and that is easier to control by
// hand than to talk a general encoder into.

// Kerberos message types (RFC 4120 §7.5.7).
const (
	krbASReq    = 10
	krbASRep    = 11
	krbTGSReq   = 12
	krbTGSRep   = 13
	krbErrorMsg = 30
)

// Encryption types. Only RC4-HMAC is produced: it is what every roasting tool
// asks for, and an account that offers only RC4 is exactly the neglected
// service account an attacker hopes to find.
const (
	etypeRC4HMAC  = 23
	etypeAES256   = 18
	etypeAES128   = 17
	etypeDESCBCMD = 3
)

// KDC error codes an attacker's tooling reads as decisions.
const (
	kdcErrPrincipalUnknown  = 6  // this user does not exist -- enumeration's answer
	kdcErrPreauthFailed     = 24 // wrong password
	kdcErrPreauthRequired   = 25 // this user exists; send a timestamp -- enumeration's other answer
	kdcErrSPrincipalUnknown = 7
	kdcErrResponseTooBig    = 52 // "use TCP", which is also our anti-amplification answer
	kdcErrEtypeNoSupp       = 14
	kdcErrPolicy            = 12
)

// Pre-authentication data types.
const (
	paTGSReq        = 1
	paEncTimestamp  = 2
	paEtypeInfo2    = 19
	paPacRequest    = 128
	paEncTimestampT = 2
)

// Principal name types.
const (
	ntPrincipal = 1
	ntSrvInst   = 2
	ntSrvHst    = 3
)

// --- writing ---------------------------------------------------------------

// derApp wraps a body in [APPLICATION n].
func derApp(n int, body []byte) []byte { return berSeq(0x60|byte(n), body) }

// derCtx wraps a body in a constructed context tag [n].
func derCtx(n int, body []byte) []byte { return berSeq(0xa0|byte(n), body) }

// derSequence wraps a body in SEQUENCE.
func derSequence(body []byte) []byte { return berSeq(0x30, body) }

// derGeneralString encodes GeneralString, which is what Kerberos uses for every
// name in a principal.
func derGeneralString(s string) []byte { return berSeq(0x1b, []byte(s)) }

// derOctetString encodes OCTET STRING.
func derOctetString(b []byte) []byte { return berSeq(0x04, b) }

// derBitString encodes BIT STRING with no unused bits, which is how KDCOptions
// and TicketFlags are carried.
func derBitString(b []byte) []byte {
	return berSeq(0x03, append([]byte{0x00}, b...))
}

// derKerberosTime encodes GeneralizedTime the way Kerberos wants it: UTC,
// second precision, trailing Z, no fractional part.
func derKerberosTime(t time.Time) []byte {
	return berSeq(0x18, []byte(t.UTC().Format("20060102150405Z")))
}

// derPrincipalName encodes PrincipalName: a name type plus its components.
func derPrincipalName(nameType int, parts ...string) []byte {
	var names []byte
	for _, p := range parts {
		names = append(names, derGeneralString(p)...)
	}
	return derSequence(append(
		derCtx(0, berInteger(nameType)),
		derCtx(1, derSequence(names))...))
}

// derEncryptedData encodes EncryptedData: which etype, which key version, and
// the blob itself.
func derEncryptedData(etype, kvno int, cipher []byte) []byte {
	body := derCtx(0, berInteger(etype))
	if kvno > 0 {
		body = append(body, derCtx(1, berInteger(kvno))...)
	}
	body = append(body, derCtx(2, derOctetString(cipher))...)
	return derSequence(body)
}

// --- reading ---------------------------------------------------------------

// krbRequest is what a KDC needs from an AS-REQ or TGS-REQ. Everything else in
// the message is parsed only far enough to be skipped: a decoy that rejected
// requests over fields it does not use would be a decoy attackers learn to
// avoid.
type krbRequest struct {
	MsgType int
	// Client is the principal asking, from the req-body cname (AS-REQ) or from
	// the PA-TGS-REQ ticket (TGS-REQ, where cname is absent).
	Client string
	// Service is the sname being asked for: krbtgt/REALM for a TGT, or the SPN
	// of the service being kerberoasted.
	Service string
	Realm   string
	// ETypes is what the client offered, in its own order of preference. An
	// attacker asking for RC4 first on a modern domain is asking to be roasted.
	ETypes []int
	// PAEncTimestamp is the encrypted pre-authentication timestamp, when the
	// client sent one. Its absence on an AS-REQ is the AS-REP roast.
	PAEncTimestamp []byte
	// PAEncEtype is the etype of that timestamp.
	PAEncEtype int
	// HasPATGSReq means the request carried a ticket, i.e. it is a real TGS-REQ.
	HasPATGSReq bool
	// RequestedPAC records whether a PAC was asked for, which distinguishes
	// tooling from a real Windows client.
	RequestedPAC bool
	// Till is the requested expiry; roasting tools ask for a long one.
	Till time.Time
}

var errKrbParse = errors.New("kerberos: malformed request")

// parseKrbRequest reads an AS-REQ or TGS-REQ.
func parseKrbRequest(b []byte) (*krbRequest, error) {
	tag, body, _, err := berNext(b)
	if err != nil {
		return nil, err
	}
	if tag != 0x60|krbASReq && tag != 0x60|krbTGSReq {
		return nil, fmt.Errorf("%w: application tag 0x%02x is not a KDC request", errKrbParse, tag)
	}
	req := &krbRequest{MsgType: int(tag & 0x1f)}

	// Inside the application tag is a SEQUENCE of context-tagged fields.
	seqTag, seq, _, err := berNext(body)
	if err != nil || seqTag != 0x30 {
		return nil, errKrbParse
	}

	rest := seq
	for len(rest) > 0 {
		var ctag byte
		var val []byte
		ctag, val, rest, err = berNext(rest)
		if err != nil {
			return nil, err
		}
		switch ctag {
		case 0xa1: // pvno
		case 0xa2: // msg-type
			if v, ok := derInt(val); ok {
				req.MsgType = v
			}
		case 0xa3: // padata
			parsePadata(val, req)
		case 0xa4: // req-body
			if err := parseReqBody(val, req); err != nil {
				return nil, err
			}
		}
	}
	if req.Realm == "" && req.Service == "" {
		return nil, errKrbParse
	}
	return req, nil
}

func parsePadata(val []byte, req *krbRequest) {
	seqTag, seq, _, err := berNext(val)
	if err != nil || seqTag != 0x30 {
		return
	}
	rest := seq
	for len(rest) > 0 {
		var entryTag byte
		var entry []byte
		entryTag, entry, rest, err = berNext(rest)
		if err != nil || entryTag != 0x30 {
			return
		}
		var paType int
		var paValue []byte
		inner := entry
		for len(inner) > 0 {
			var t byte
			var v []byte
			t, v, inner, err = berNext(inner)
			if err != nil {
				return
			}
			switch t {
			case 0xa1:
				if n, ok := derInt(v); ok {
					paType = n
				}
			case 0xa2:
				if _, ov, _, err := berNext(v); err == nil {
					paValue = ov
				}
			}
		}
		switch paType {
		case paEncTimestamp:
			req.PAEncTimestamp, req.PAEncEtype = parseEncryptedData(paValue)
		case paTGSReq:
			req.HasPATGSReq = true
		case paPacRequest:
			req.RequestedPAC = true
		}
	}
}

// parseEncryptedData pulls the etype and cipher out of an EncryptedData.
func parseEncryptedData(b []byte) (cipher []byte, etype int) {
	seqTag, seq, _, err := berNext(b)
	if err != nil || seqTag != 0x30 {
		return nil, 0
	}
	rest := seq
	for len(rest) > 0 {
		var t byte
		var v []byte
		t, v, rest, err = berNext(rest)
		if err != nil {
			return nil, 0
		}
		switch t {
		case 0xa0:
			if n, ok := derInt(v); ok {
				etype = n
			}
		case 0xa2:
			if _, ov, _, err := berNext(v); err == nil {
				cipher = ov
			}
		}
	}
	return cipher, etype
}

func parseReqBody(val []byte, req *krbRequest) error {
	seqTag, seq, _, err := berNext(val)
	if err != nil || seqTag != 0x30 {
		return errKrbParse
	}
	rest := seq
	for len(rest) > 0 {
		var t byte
		var v []byte
		t, v, rest, err = berNext(rest)
		if err != nil {
			return err
		}
		switch t {
		case 0xa1: // cname
			req.Client = joinPrincipal(v)
		case 0xa2: // realm
			if _, sv, _, err := berNext(v); err == nil {
				req.Realm = string(sv)
			}
		case 0xa3: // sname
			req.Service = joinPrincipal(v)
		case 0xa5: // till
			if _, tv, _, err := berNext(v); err == nil {
				if ts, err := time.Parse("20060102150405Z", string(tv)); err == nil {
					req.Till = ts
				}
			}
		case 0xa8: // etype
			req.ETypes = parseEtypes(v)
		}
	}
	return nil
}

// joinPrincipal renders a PrincipalName the way people write it: components
// joined by "/", which is also how an SPN is written.
func joinPrincipal(b []byte) string {
	seqTag, seq, _, err := berNext(b)
	if err != nil || seqTag != 0x30 {
		return ""
	}
	var parts []string
	rest := seq
	for len(rest) > 0 {
		var t byte
		var v []byte
		t, v, rest, err = berNext(rest)
		if err != nil {
			return strings.Join(parts, "/")
		}
		if t != 0xa1 {
			continue
		}
		inner := v
		if seqTag, sv, _, err := berNext(inner); err == nil && seqTag == 0x30 {
			inner = sv
		}
		for len(inner) > 0 {
			var st byte
			var sv []byte
			st, sv, inner, err = berNext(inner)
			if err != nil {
				break
			}
			if st == 0x1b {
				parts = append(parts, string(sv))
			}
		}
	}
	return strings.Join(parts, "/")
}

func parseEtypes(b []byte) []int {
	seqTag, seq, _, err := berNext(b)
	if err != nil || seqTag != 0x30 {
		return nil
	}
	var out []int
	rest := seq
	for len(rest) > 0 {
		var t byte
		var v []byte
		t, v, rest, err = berNext(rest)
		if err != nil {
			return out
		}
		if t == 0x02 {
			if n, ok := derIntBytes(v); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// derInt reads an INTEGER that is still wrapped in its tag.
func derInt(b []byte) (int, bool) {
	t, v, _, err := berNext(b)
	if err != nil || t != 0x02 {
		return 0, false
	}
	return derIntBytes(v)
}

// derIntBytes reads the contents of an INTEGER.
func derIntBytes(v []byte) (int, bool) {
	if len(v) == 0 || len(v) > 4 {
		return 0, false
	}
	n := 0
	for _, b := range v {
		n = n<<8 | int(b)
	}
	return n, true
}
