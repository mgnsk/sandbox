// Package mitmca is a throwaway certificate authority for an
// HTTPS-intercepting guard proxy.
//
// Each proxy makes its own at startup. The key lives only in that process's
// memory and dies with it; only the certificate leaves it, into the bundle
// the sandbox's gh and fj wrappers trust. Leaf certificates are minted on
// demand, one per host the proxy is asked to CONNECT to.
package mitmca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	// Leaves outlive any sandbox session; the CA itself dies with the proxy.
	leafValidity = 30 * 24 * time.Hour
	caValidity   = 365 * 24 * time.Hour
	// Some slack for clock differences between host and clients.
	backdate = time.Hour
)

// CA is a CA key and certificate, and a TLS config per host signed by it.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte

	mu      sync.Mutex
	configs map[string]*tls.Config
}

// serial is a random serial number: 159 bits, positive in 20 bytes as RFC
// 5280 asks.
func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
}

// New makes a CA named name.
func New(name string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{key: key, cert: cert, der: der, configs: map[string]*tls.Config{}}, nil
}

// PEM is the CA certificate, PEM-encoded.
func (ca *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
}

// Config is a server-side TLS config presenting a certificate for host (a
// DNS name or IP address, without a port).
func (ca *CA) Config(host string) (*tls.Config, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cfg, ok := ca.configs[host]; ok {
		return cfg, nil
	}
	leaf, err := ca.leaf(host)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
		// The proxy's inner server speaks HTTP/1.1 only.
		NextProtos: []string{"http/1.1"},
	}
	ca.configs[host] = cfg
	return cfg, nil
}

func (ca *CA) leaf(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sn, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(leafValidity),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.der}, PrivateKey: key}, nil
}
