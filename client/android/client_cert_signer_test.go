package android

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeHardware stands in for a security key: it holds the private key and signs
// digests handed to it, exactly as the app-side implementation will. It records
// which algorithm was asked for, because getting that mapping wrong is the
// failure that shows up only as a generic handshake error.
type fakeHardware struct {
	key       *ecdsa.PrivateKey
	asked     []string
	refuseAll bool
}

func (f *fakeHardware) Sign(digest []byte, algorithm string) ([]byte, error) {
	f.asked = append(f.asked, algorithm)
	if f.refuseAll {
		return nil, fmt.Errorf("no")
	}
	// The digest arrives already hashed, which is what the interface promises.
	return ecdsa.SignASN1(rand.Reader, f.key, digest)
}

// The point of the whole path: a real TLS handshake completes against a server
// that demands a client certificate, with the private key reachable only
// through the interface.
func TestHardwareSignerCompletesATLSHandshake(t *testing.T) {
	chainPEM, key := testCertificate(t)
	hardware := &fakeHardware{key: key}

	cert, err := certificateFromPEM(chainPEM)
	if err != nil {
		t.Fatalf("certificateFromPEM: %v", err)
	}
	cert.PrivateKey = &hardwareSigner{public: cert.Leaf.PublicKey, signer: hardware}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("handshake with the hardware-held key failed: %v", err)
	}
	defer resp.Body.Close()

	if len(hardware.asked) == 0 {
		t.Fatal("the signer was never called: the key was not the one used")
	}
	for _, algorithm := range hardware.asked {
		if algorithm[:5] != "ECDSA" {
			t.Fatalf("asked for %q on an EC key", algorithm)
		}
	}
}

// A refusal has to surface as a handshake failure, not as a connection that
// silently proceeds without a certificate.
func TestHardwareSignerRefusalFailsTheHandshake(t *testing.T) {
	chainPEM, key := testCertificate(t)
	cert, err := certificateFromPEM(chainPEM)
	if err != nil {
		t.Fatalf("certificateFromPEM: %v", err)
	}
	cert.PrivateKey = &hardwareSigner{
		public: cert.Leaf.PublicKey,
		signer: &fakeHardware{key: key, refuseAll: true},
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{*cert}

	resp, err := client.Get(server.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the handshake succeeded even though the signer refused")
	}
}

func TestCertificateFromPEMKeepsTheWholeChain(t *testing.T) {
	chainPEM, _ := testCertificate(t)
	// Two copies of the same certificate stand in for leaf + intermediate.
	cert, err := certificateFromPEM(append(append([]byte{}, chainPEM...), chainPEM...))
	if err != nil {
		t.Fatalf("certificateFromPEM: %v", err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain of %d, want both blocks kept", len(cert.Certificate))
	}
	if cert.Leaf == nil {
		t.Fatal("leaf not parsed")
	}
}

func TestCertificateFromPEMRejectsGarbage(t *testing.T) {
	if _, err := certificateFromPEM([]byte("not a certificate")); err == nil {
		t.Fatal("garbage was accepted as a certificate")
	}
}

func testCertificate(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hardware-held"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}
