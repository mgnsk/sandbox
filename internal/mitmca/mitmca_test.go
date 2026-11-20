package mitmca

import (
	"crypto/x509"
	"testing"
)

// A guard's CA is trusted by every client inside, for any name; its name
// constraints keep what it can sign for to the guard's own hosts.
func TestACAOnlySignsForItsHosts(t *testing.T) {
	ca, err := New("test", "api.example", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	verify := func(ca *CA, host string) error {
		cfg, err := ca.Config(host)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host})
		return err
	}
	for host, valid := range map[string]bool{
		"api.example":     true,
		"sub.api.example": true, // As name constraints go.
		"192.0.2.1":       true,
		"example":         false,
		"evil.example":    false,
		"bank.example":    false,
		"192.0.2.2":       false,
		"::1":             false,
	} {
		if err := verify(ca, host); (err == nil) != valid {
			t.Errorf("%s: %v", host, err)
		}
	}

	// Names only: no address at all.
	names, _ := New("test", "api.example")
	pool = x509.NewCertPool()
	pool.AddCert(names.cert)
	if verify(names, "api.example") != nil || verify(names, "192.0.2.1") == nil {
		t.Error("a CA for a name signs for an address")
	}
	// Without hosts, unconstrained: the test upstreams'.
	any, _ := New("test")
	pool = x509.NewCertPool()
	pool.AddCert(any.cert)
	if err := verify(any, "whatever.example"); err != nil {
		t.Error(err)
	}
}
