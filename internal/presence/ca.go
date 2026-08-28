package presence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PKI is the small certificate authority that makes mutual TLS on the overlay
// something an operator will actually turn on.
//
// A feature that requires a separate PKI project before it can be used is a
// feature that stays off, and an overlay tunnel that stays unencrypted carries
// the agent token in clear text across a customer network. So MIRAGE issues its
// own: one CA, one hub certificate, one certificate per agent. It is a private
// CA for one purpose and is trusted by nothing else, which is exactly right --
// the hub should accept MIRAGE agents, not anything a public CA has ever
// signed.
type PKI struct {
	// Dir is where the material is written. Keys land there with mode 0600 and
	// the directory itself with 0700.
	Dir string
	// Hosts are the names and addresses an agent may use to reach the hub.
	// They become the hub certificate's SANs, so a wrong one here shows up as
	// a handshake failure rather than as silent acceptance.
	Hosts []string
	// Agents are the agent ids to issue client certificates for. Each id
	// becomes the certificate's common name, so a hub log records which
	// certificate connected and not merely that one did.
	Agents []string
	// Validity bounds the leaf certificates. The CA lives ten times as long.
	Validity time.Duration
}

// IssuedFile is one file the PKI wrote.
type IssuedFile struct {
	Role string // "ca", "hub" or an agent id
	Kind string // "certificate" or "key"
	Path string
}

// Generate writes the CA, the hub certificate and one certificate per agent.
//
// It refuses to overwrite anything: re-running it against a live deployment
// would silently invalidate every agent still holding the old material, and an
// operator who wants a new CA can say so by removing the old directory.
func (p PKI) Generate() ([]IssuedFile, error) {
	if p.Dir == "" {
		return nil, fmt.Errorf("presence: no output directory for the CA")
	}
	if len(p.Hosts) == 0 {
		return nil, fmt.Errorf("presence: the hub certificate needs at least one host or address")
	}
	if len(p.Agents) == 0 {
		return nil, fmt.Errorf("presence: no agent ids; nothing would be able to connect")
	}
	validity := p.Validity
	if validity <= 0 {
		validity = 2 * 365 * 24 * time.Hour
	}
	seen := map[string]bool{}
	for _, a := range p.Agents {
		if strings.TrimSpace(a) == "" {
			return nil, fmt.Errorf("presence: an agent id is empty")
		}
		if seen[a] {
			return nil, fmt.Errorf("presence: duplicate agent id %q", a)
		}
		seen[a] = true
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return nil, err
	}

	now := time.Now().Add(-5 * time.Minute) // tolerate a little clock skew

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: "MIRAGE Presence CA", Organization: []string{"MIRAGE"}},
		NotBefore:             now,
		NotAfter:              now.Add(10 * validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	var out []IssuedFile
	write := func(role, kind, name string, data []byte, mode os.FileMode) error {
		path := filepath.Join(p.Dir, name)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("presence: %s already exists; "+
				"remove the directory to issue a new CA, but every agent will need the new material", path)
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
		out = append(out, IssuedFile{Role: role, Kind: kind, Path: path})
		return nil
	}

	if err := write("ca", "certificate", "ca.crt", certPEM(caDER), 0o644); err != nil {
		return nil, err
	}
	caKeyPEM, err := keyPEM(caKey)
	if err != nil {
		return nil, err
	}
	if err := write("ca", "key", "ca.key", caKeyPEM, 0o600); err != nil {
		return nil, err
	}

	issue := func(role, name, cn string, hosts []string, server bool) error {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: mustSerial(),
			Subject:      pkix.Name{CommonName: cn, Organization: []string{"MIRAGE"}},
			NotBefore:    now,
			NotAfter:     now.Add(validity),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			for _, h := range hosts {
				if ip := net.ParseIP(h); ip != nil {
					tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
				} else {
					tmpl.DNSNames = append(tmpl.DNSNames, h)
				}
			}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err := write(role, "certificate", name+".crt", certPEM(der), 0o644); err != nil {
			return err
		}
		kp, err := keyPEM(key)
		if err != nil {
			return err
		}
		return write(role, "key", name+".key", kp, 0o600)
	}

	if err := issue("hub", "hub", "mirage-hub", p.Hosts, true); err != nil {
		return nil, err
	}
	for _, id := range p.Agents {
		if err := issue(id, "agent-"+safeName(id), id, nil, false); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// safeName keeps an agent id from escaping the output directory or colliding
// with the CA's own files.
func safeName(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func mustSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// crypto/rand failing is not a condition to paper over.
		panic("presence: no randomness for a certificate serial: " + err.Error())
	}
	return n
}
