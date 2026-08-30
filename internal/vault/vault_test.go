package vault

import (
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSealRoundTripAndTamperDetection(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	seal := kp.SealHead("acme", "hq", 4242, "deadbeefcafe", now)

	// A freshly signed seal verifies.
	if err := VerifySeal(seal); err != nil {
		t.Fatalf("a valid seal did not verify: %v", err)
	}

	// Any change to what the seal attests must break the signature -- that is
	// the whole point: a court must be able to tell an altered seal from a real
	// one.
	for _, mut := range []func(*Seal){
		func(s *Seal) { s.HeadHash = "0000" },
		func(s *Seal) { s.HeadSeq = 4243 },
		func(s *Seal) { s.TenantID = "evil" },
		func(s *Seal) { s.SealedAt = now.Add(time.Hour) },
	} {
		tampered := *seal
		mut(&tampered)
		if err := VerifySeal(&tampered); err == nil {
			t.Fatal("a tampered seal verified as valid")
		}
	}
}

func TestSealFromADifferentKeyDoesNotVerify(t *testing.T) {
	a, _ := GenerateKeypair()
	b, _ := GenerateKeypair()
	seal := a.SealHead("t", "s", 1, "hash", time.Now())
	// Swap in b's public key: the signature no longer matches the key.
	seal.PublicKey = Fingerprint(b.Public) // deliberately wrong shape too
	if err := VerifySeal(seal); err == nil {
		t.Fatal("a seal with a swapped key verified")
	}
}

func TestKeyPersistsAndReloads(t *testing.T) {
	kp, _ := GenerateKeypair()
	path := filepath.Join(t.TempDir(), "vault.key")
	if err := kp.SaveKey(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	// A seal signed before saving must verify after reload, i.e. it is the same
	// identity.
	seal := kp.SealHead("t", "s", 7, "abc", time.Now())
	seal2 := loaded.SealHead("t", "s", 7, "abc", seal.SealedAt)
	if seal.Signature != seal2.Signature {
		t.Fatal("the reloaded key produced a different signature")
	}
}

func TestKeyFileIsNotWorldReadable(t *testing.T) {
	kp, _ := GenerateKeypair()
	path := filepath.Join(t.TempDir(), "vault.key")
	kp.SaveKey(path)
	// The private key is the deployment's identity; it must be 0600.
	// (checked via a stat in a portable way)
	if perm := statPerm(t, path); perm&0o077 != 0 {
		t.Fatalf("the vault key is group/other readable: %o", perm)
	}
}

func TestTimeStampRequestIsWellFormed(t *testing.T) {
	// The request must be valid DER an actual TSA would accept: version 1, the
	// SHA-256 imprint, certReq true.
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i)
	}
	req, err := TimeStampRequest(digest)
	if err != nil {
		t.Fatal(err)
	}
	var parsed timeStampReq
	if _, err := asn1.Unmarshal(req, &parsed); err != nil {
		t.Fatalf("our own request is not valid DER: %v", err)
	}
	if parsed.Version != 1 {
		t.Fatalf("version is %d, want 1", parsed.Version)
	}
	if !parsed.MessageImprint.HashAlgorithm.Algorithm.Equal(sha256OID) {
		t.Fatal("the request does not declare SHA-256")
	}
	if !parsed.CertReq {
		t.Fatal("certReq must be true so the TSA includes its certificate")
	}
	if string(parsed.MessageImprint.HashedMessage) != string(digest[:]) {
		t.Fatal("the digest in the request does not match")
	}
}

func TestExtractGenTimeFromATokenLikeStructure(t *testing.T) {
	// A GeneralizedTime (tag 0x18) embedded the way a TSTInfo carries genTime.
	// This proves the extractor reads the "when" a real token asserts.
	gt := "20260318120000Z"
	token := append([]byte{0x18, byte(len(gt))}, []byte(gt)...)
	// Prefix some unrelated DER so the scan has to find it, not assume position.
	token = append([]byte{0x30, 0x03, 0x02, 0x01, 0x05}, token...)
	got, err := ExtractGenTime(token)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("genTime = %v, want %v", got, want)
	}
}

func TestHeadDigestBindsSeqAndHash(t *testing.T) {
	// The timestamp is requested over seq+hash together, so a token cannot be
	// replayed onto a different head.
	a := (&Seal{HeadSeq: 1, HeadHash: "x"}).HeadDigest()
	b := (&Seal{HeadSeq: 2, HeadHash: "x"}).HeadDigest()
	c := (&Seal{HeadSeq: 1, HeadHash: "y"}).HeadDigest()
	if a == b || a == c {
		t.Fatal("the digest does not bind both seq and hash")
	}
}

func statPerm(t *testing.T, path string) uint32 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(fi.Mode().Perm())
}
