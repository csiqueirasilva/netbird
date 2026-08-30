//go:build pkcs11hw

package profilemanager

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"
)

// Exercises discovery and signing on a real token, against a server that
// requires mTLS. Behind the `pkcs11hw` tag because it needs hardware plugged in.
//
//	go test -tags pkcs11hw ./client/internal/profilemanager/ -run PKCS11Hardware -v
//
// Variables: NB_PKCS11_MODULE, NB_PKCS11_PIN, and optionally NB_PKCS11_SERIAL
// (to pin a token) and NB_PKCS11_URL (an endpoint behind a client-cert gate).
func TestPKCS11HardwareTokenListing(t *testing.T) {
	module := os.Getenv("NB_PKCS11_MODULE")
	if module == "" {
		t.Skip("NB_PKCS11_MODULE not set")
	}

	tokens, err := ListTokens(module)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("no token found: is it plugged in?")
	}
	for _, token := range tokens {
		t.Logf("token: %s", token)
	}
}

func TestPKCS11HardwareHandshake(t *testing.T) {
	cfg := PKCS11Config{
		ModulePath:  os.Getenv("NB_PKCS11_MODULE"),
		TokenSerial: os.Getenv("NB_PKCS11_SERIAL"),
		Pin:         os.Getenv("NB_PKCS11_PIN"),
	}
	if !cfg.IsSet() {
		t.Skip("NB_PKCS11_MODULE not set")
	}

	certificates, err := LoadPKCS11Certificates(cfg)
	if err != nil {
		t.Fatalf("load certificates from the token: %v", err)
	}
	if len(certificates) == 0 {
		t.Fatal("no client certificate discovered on the token")
	}
	for _, cert := range certificates {
		t.Logf("discovered %q, chain of %d", cert.Leaf.Subject, len(cert.Certificate))
		if cert.Leaf.IsCA {
			t.Errorf("a CA certificate was offered as a client identity: %q", cert.Leaf.Subject)
		}
	}

	url := os.Getenv("NB_PKCS11_URL")
	if url == "" {
		t.Skip("NB_PKCS11_URL not set")
	}

	// Every discovered certificate is offered: crypto/tls presents whichever
	// matches the CAs the server names in its CertificateRequest. That choice is
	// what replaced the certificate label the profile used to carry.
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{Certificates: certificates},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("handshake with the token's certificate failed: %v", err)
	}
	defer resp.Body.Close()

	// 403 means the gate refused the certificate, or none was presented.
	// Anything else means the request went through it.
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("gate refused: HTTP 403 -- the token's certificate was not accepted")
	}
	t.Logf("passed the gate: HTTP %d (403 would be a refusal)", resp.StatusCode)
}

// Discovery is what removes the last thing anyone had to write down. It has to
// find the driver on a machine where the token actually works.
func TestPKCS11HardwareDiscovery(t *testing.T) {
	candidates := DiscoverModules()
	if len(candidates) == 0 {
		t.Fatalf("no PKCS#11 driver discovered. Looked in: %v", SearchedModulePaths())
	}
	for _, candidate := range candidates {
		t.Logf("driver %s sees %d token(s)", candidate.Path, len(candidate.Tokens))
		for _, token := range candidate.Tokens {
			t.Logf("    %s", token)
		}
	}
}
