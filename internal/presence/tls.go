package presence

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSConfig configures transport security for the overlay tunnel.
//
// The tunnel carries an attacker's traffic and the agent's token across
// whatever network sits between a customer segment and the hub. Without TLS
// both are readable by anyone on the path, and the token is the only thing
// stopping someone from projecting decoys of their own into the platform.
//
// Mutual TLS is the intended configuration: the agent proves it is the agent,
// the hub proves it is the hub, and the shared token remains as a second
// factor rather than the only one.
type TLSConfig struct {
	// CertFile and KeyFile are this side's certificate. Required on the hub to
	// enable TLS at all; optional on the agent unless the hub demands a client
	// certificate.
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
	// CAFile verifies the other side: on the hub it is the CA that signs agent
	// certificates; on the agent it is the CA that signed the hub's.
	CAFile string `yaml:"ca_file" json:"ca_file"`
	// ServerName is what the agent expects on the hub's certificate. Leave it
	// empty to use the host it dialled.
	ServerName string `yaml:"server_name" json:"server_name"`
	// InsecureSkipVerify disables verification of the hub's certificate. It
	// exists for a lab and is refused when a CA is configured, because a
	// deployment that sets both has almost certainly made a mistake.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// Enabled reports whether any TLS setting was supplied.
func (c TLSConfig) Enabled() bool {
	return c.CertFile != "" || c.KeyFile != "" || c.CAFile != "" || c.InsecureSkipVerify
}

// ServerConfig builds the hub's TLS configuration.
func (c TLSConfig) ServerConfig() (*tls.Config, error) {
	if c.CertFile == "" || c.KeyFile == "" {
		return nil, errors.New("presence: TLS on the hub needs both cert_file and key_file")
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("presence: load hub certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if c.CAFile != "" {
		pool, err := loadCA(c.CAFile)
		if err != nil {
			return nil, err
		}
		// With a client CA configured, an agent without a valid certificate is
		// refused before it can even offer a token.
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ClientConfig builds the agent's TLS configuration.
func (c TLSConfig) ClientConfig() (*tls.Config, error) {
	if c.InsecureSkipVerify && c.CAFile != "" {
		return nil, errors.New("presence: insecure_skip_verify and ca_file are contradictory; " +
			"pick one and mean it")
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}
	if c.CAFile != "" {
		pool, err := loadCA(c.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if c.CertFile != "" || c.KeyFile != "" {
		if c.CertFile == "" || c.KeyFile == "" {
			return nil, errors.New("presence: an agent certificate needs both cert_file and key_file")
		}
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("presence: load agent certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("presence: read CA %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("presence: %s contains no usable certificate", path)
	}
	return pool, nil
}
