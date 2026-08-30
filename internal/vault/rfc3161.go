package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RFC 3161 is the standard for trusted timestamping: a client sends the SHA-256
// of what it wants dated to a Time Stamping Authority, and the TSA returns a
// signed token asserting that hash existed at a genTime. A court or an auditor
// trusts the TSA, not the operator, which is the whole point -- the operator
// cannot backdate evidence they do not control the clock for.
//
// MIRAGE builds the request, fetches the token, stores it raw in the seal, and
// can read the genTime out of it. It deliberately does not re-implement the
// TSA's signature verification: the token is a standard CMS structure, and a
// verifier confirms it with `openssl ts -verify` against the TSA's certificate,
// which is stronger evidence than anything MIRAGE could assert about itself.

// sha256OID is the algorithm identifier for the message imprint.
var sha256OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	CertReq        bool `asn1:"optional"`
}

// TimeStampRequest builds a DER-encoded RFC 3161 request over a SHA-256 digest.
// CertReq is set so the TSA includes its certificate in the response, which is
// what a later `openssl ts -verify` needs.
func TimeStampRequest(digest [32]byte) ([]byte, error) {
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm:  sha256OID,
				Parameters: asn1.RawValue{Tag: asn1.TagNull, FullBytes: []byte{0x05, 0x00}},
			},
			HashedMessage: digest[:],
		},
		CertReq: true,
	}
	return asn1.Marshal(req)
}

// FetchTimestamp sends a timestamp request to a TSA over HTTP and returns the
// raw DER response token. tsaURL is a public or private RFC 3161 endpoint (for
// example https://freetsa.org/tsr). The token is stored verbatim; MIRAGE never
// alters it.
func FetchTimestamp(ctx context.Context, tsaURL string, digest [32]byte) ([]byte, error) {
	body, err := TimeStampRequest(digest)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: contact TSA %s: %w", tsaURL, err)
	}
	defer resp.Body.Close()
	token, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: TSA %s returned HTTP %d", tsaURL, resp.StatusCode)
	}
	if len(token) < 8 {
		return nil, fmt.Errorf("vault: TSA %s returned an empty token", tsaURL)
	}
	return token, nil
}

// ExtractGenTime reads the genTime out of an RFC 3161 response token.
//
// It scans the DER for the TSTInfo's GeneralizedTime rather than fully decoding
// the CMS envelope: the goal here is only to show a human when the token says
// the evidence existed. The token's authority still rests on the TSA's
// signature, which a verifier checks with standard tools.
func ExtractGenTime(token []byte) (time.Time, error) {
	// Walk the DER looking for the first GeneralizedTime (tag 0x18) whose
	// contents parse as an RFC 3161 timestamp. TSTInfo places genTime after the
	// message imprint, and no earlier GeneralizedTime appears in a well-formed
	// token, so the first is the one we want.
	for i := 0; i+2 < len(token); i++ {
		if token[i] != 0x18 {
			continue
		}
		ln := int(token[i+1])
		if ln <= 0 || ln > 32 || i+2+ln > len(token) {
			continue
		}
		raw := string(token[i+2 : i+2+ln])
		if t, ok := parseGeneralizedTime(raw); ok {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("vault: no genTime found in the timestamp token")
}

func parseGeneralizedTime(s string) (time.Time, bool) {
	for _, layout := range []string{
		"20060102150405Z", "20060102150405.0Z", "20060102150405.00Z", "20060102150405.000Z",
		"20060102150405-0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// DigestOf is a convenience for callers timestamping arbitrary bytes.
func DigestOf(b []byte) [32]byte { return sha256.Sum256(b) }
