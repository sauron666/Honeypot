// Package vault turns MIRAGE's internal hash chain into evidence a third party
// can trust.
//
// The append-only chain proves the evidence has not been altered *since MIRAGE
// wrote it*. That is necessary but not sufficient for a courtroom or an auditor,
// who will ask two further questions the chain alone cannot answer: who says
// this is MIRAGE's evidence and not something you fabricated, and when did it
// exist? A hash chain a defendant produces themselves answers neither.
//
// The vault answers both. It signs the chain head with a long-lived key, so
// anyone holding the public key can confirm the evidence came from this
// deployment and its head has not been swapped. And it obtains an RFC 3161
// trusted timestamp over that head from an independent Time Stamping Authority,
// so a third party attests the evidence existed at a point in time that the
// operator could not backdate. Together they turn "trust our log" into
// "verify it yourself".
package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// Seal is a signed attestation of an evidence chain's head at a moment in time.
//
// It is the small, portable object a deployment publishes or archives: given
// the public key, anyone can verify the seal without the evidence file, and
// given the evidence file too, they can verify the file's head matches.
type Seal struct {
	// TenantID and SiteID identify the deployment, so a seal names its source.
	TenantID string `json:"tenant_id"`
	SiteID   string `json:"site_id"`
	// HeadSeq and HeadHash are the chain head this seal attests.
	HeadSeq  uint64 `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	// SealedAt is when this deployment signed it (its own clock, untrusted).
	SealedAt time.Time `json:"sealed_at"`
	// PublicKey is the ed25519 verifying key, hex-encoded, so a verifier needs
	// nothing but the seal itself to check the signature.
	PublicKey string `json:"public_key"`
	// Signature is over the canonical bytes of the fields above.
	Signature string `json:"signature"`
	// Timestamp, when present, is the DER-encoded RFC 3161 timestamp token from
	// a TSA, hex-encoded. It is what makes the "when" answerable by a third
	// party rather than by the operator's clock.
	Timestamp string `json:"rfc3161_timestamp,omitempty"`
	// TimestampAuthority names the TSA, for the reader's benefit.
	TimestampAuthority string `json:"timestamp_authority,omitempty"`
}

// signingBytes is the exact, canonical byte sequence a seal's signature covers.
// It deliberately excludes the signature and the timestamp: the signature
// cannot cover itself, and the RFC 3161 token is obtained *over the head hash*
// independently, so it is not part of what the deployment signs.
func (s *Seal) signingBytes() []byte {
	return []byte(fmt.Sprintf("mirage-seal-v1\n%s\n%s\n%d\n%s\n%s\n",
		s.TenantID, s.SiteID, s.HeadSeq, s.HeadHash, s.SealedAt.UTC().Format(time.RFC3339Nano)))
}

// Keypair is a deployment's long-lived signing identity.
type Keypair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// GenerateKeypair mints a new signing identity.
func GenerateKeypair() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keypair{Private: priv, Public: pub}, nil
}

// SaveKey writes the private key as PEM with owner-only permissions. The key is
// the deployment's identity; whoever holds it can sign evidence as this
// deployment, so it is written 0600 and belongs in the same guarded place as
// the evidence.
func (k *Keypair) SaveKey(path string) error {
	der, err := marshalPrivate(k.Private)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "MIRAGE VAULT PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// LoadKey reads a private key written by SaveKey.
func LoadKey(path string) (*Keypair, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("vault: %s is not a PEM key", path)
	}
	priv, err := parsePrivate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Keypair{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

// SealHead signs an evidence chain head, producing a portable, verifiable seal.
func (k *Keypair) SealHead(tenant, site string, headSeq uint64, headHash string, now time.Time) *Seal {
	s := &Seal{
		TenantID: tenant, SiteID: site,
		HeadSeq: headSeq, HeadHash: headHash,
		SealedAt:  now.UTC(),
		PublicKey: hex.EncodeToString(k.Public),
	}
	s.Signature = hex.EncodeToString(ed25519.Sign(k.Private, s.signingBytes()))
	return s
}

// VerifySeal checks a seal's signature against the public key embedded in it.
//
// It returns an error rather than a bool so the reason a seal fails -- a bad
// signature, a malformed key -- is legible to whoever is verifying evidence,
// which is exactly the audience that needs to know precisely why.
func VerifySeal(s *Seal) error {
	pub, err := hex.DecodeString(s.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("vault: seal has an invalid public key")
	}
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("vault: seal has an invalid signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), s.signingBytes(), sig) {
		return fmt.Errorf("vault: seal signature does not verify -- the seal was altered or is not from this key")
	}
	return nil
}

// HeadDigest is the SHA-256 the RFC 3161 timestamp is requested over. It binds
// the timestamp to the exact head the seal attests: seq and hash together, so a
// timestamp cannot be replayed onto a different head.
func (s *Seal) HeadDigest() [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%d\n%s", s.HeadSeq, s.HeadHash)))
}

// WriteSeal writes a seal as indented JSON.
func WriteSeal(s *Seal, path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ReadSeal reads a seal written by WriteSeal.
func ReadSeal(path string) (*Seal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Seal
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("vault: %s is not a seal: %w", path, err)
	}
	return &s, nil
}

// Fingerprint is a short, human-comparable identifier for a public key, so an
// operator can confirm out-of-band that two seals came from the same key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:8])
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+4])
	}
	return b.String()
}

// FingerprintHex returns the short fingerprint for a hex-encoded public key,
// so a verifier holding only a seal (where the key is hex) can display it.
func FingerprintHex(hexPub string) string {
	pub, err := hex.DecodeString(hexPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "invalid-key"
	}
	return Fingerprint(ed25519.PublicKey(pub))
}
