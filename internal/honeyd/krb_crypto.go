package honeyd

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// This file implements RC4-HMAC (etype 23, RFC 4757), the encryption type every
// Kerberos roasting attack asks for.
//
// It is here because a decoy KDC that handed out random bytes would be caught
// in seconds: the attacker's tool would fail to parse them, or hashcat would
// chew through a wordlist and never find a candidate, and both are tells. What
// this produces is a genuine RC4-HMAC blob over a genuine DER structure,
// encrypted with the NT hash of the password planted on that account.
//
// So the attacker's crack succeeds. That is the point. What they walk away with
// is a working-looking credential for an account that does not exist, and the
// moment they try it anywhere in the deployment the honeytoken watcher connects
// the offline crack to the online attempt -- one attacker, two planes, one
// engagement. No amount of blob-shaped noise would do that.

// ntHash is MD4 of the UTF-16LE password: the key RC4-HMAC Kerberos uses, and
// the same value NTLM uses, which is why cracking one gives the attacker both.
func ntHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// Key usage numbers, from RFC 4120. They matter: a blob encrypted with the
// wrong usage decrypts to nothing under the right password, so the attacker's
// crack would fail and the bait would be wasted.
const (
	// krbUsageTicket is the service ticket's enc-part, the one kerberoasting
	// takes away.
	krbUsageTicket = 2
	// krbUsageASRepPart is the AS-REP enc-part encrypted under the client's own
	// key -- the one AS-REP roasting takes away.
	krbUsageASRepPart = 8
	// krbUsagePAEncTimestamp is the pre-authentication timestamp the client
	// encrypts to prove it knows the password.
	krbUsagePAEncTimestamp = 1
)

// rc4Usage applies the remap RFC 4757 §3 requires.
func rc4Usage(usage int) uint32 {
	switch usage {
	case 3, 9:
		return 8
	}
	return uint32(usage)
}

// rc4Encrypt produces checksum || RC4(K3, confounder||plaintext).
//
// confounder is a parameter rather than random inside so that a test can pin
// the output and so that a decoy is deterministic for a given deployment seed:
// two runs of the same deployment must hand an attacker the same bait, or the
// bait itself becomes the tell.
func rc4Encrypt(key []byte, usage int, confounder, plaintext []byte) ([]byte, error) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], rc4Usage(usage))

	k1 := hmacMD5(key, t[:])
	data := make([]byte, 0, len(confounder)+len(plaintext))
	data = append(data, confounder...)
	data = append(data, plaintext...)

	checksum := hmacMD5(k1, data)
	k3 := hmacMD5(k1, checksum)

	c, err := rc4.NewCipher(k3)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)

	return append(append([]byte{}, checksum...), out...), nil
}

// rc4Decrypt reverses rc4Encrypt and verifies the checksum. It is how the KDC
// checks a pre-authentication timestamp, which is how a password spray against
// this decoy is recognised as a spray rather than as noise.
func rc4Decrypt(key []byte, usage int, blob []byte) ([]byte, bool) {
	if len(blob) < md5.Size+8 {
		return nil, false
	}
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], rc4Usage(usage))

	checksum := blob[:md5.Size]
	k1 := hmacMD5(key, t[:])
	k3 := hmacMD5(k1, checksum)

	c, err := rc4.NewCipher(k3)
	if err != nil {
		return nil, false
	}
	data := make([]byte, len(blob)-md5.Size)
	c.XORKeyStream(data, blob[md5.Size:])

	if !hmac.Equal(hmacMD5(k1, data), checksum) {
		return nil, false
	}
	return data[8:], true // drop the confounder
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// asrepHash renders what an AS-REP roast yields, in the form the attacker's
// tooling prints and hashcat mode 18200 consumes.
//
// Recording it is not a courtesy to the attacker. It is what lets an analyst
// answer the only question that matters after a roast: which credential did
// they walk away with, and therefore what will they try next.
func asrepHash(user, realm string, blob []byte) string {
	if len(blob) < md5.Size {
		return ""
	}
	return fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s",
		user, strings.ToUpper(realm),
		hex.EncodeToString(blob[:md5.Size]), hex.EncodeToString(blob[md5.Size:]))
}

// tgsHash renders a kerberoast in hashcat mode 13100 form.
func tgsHash(user, realm, spn string, blob []byte) string {
	if len(blob) < md5.Size {
		return ""
	}
	return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s$%s",
		user, strings.ToUpper(realm), spn,
		hex.EncodeToString(blob[:md5.Size]), hex.EncodeToString(blob[md5.Size:]))
}
