package server

import (
	"crypto/tls"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// The PIN arrives with one login request and is not kept, so a later config read
// cannot reload the certificate. Losing it there is invisible: the login
// succeeds and the tunnel is refused afterwards, with nothing connecting the
// two. This is the guard for that.
func TestPKCS11CertificatesSurviveAConfigReload(t *testing.T) {
	s := &Server{}
	certs := []tls.Certificate{{Certificate: [][]byte{{1, 2, 3}}}}
	s.rememberPKCS11Certificates(certs)

	// A config as it comes back from disk: the token is configured, the
	// certificate is not loaded, because there was no PIN to load it with.
	config := &profilemanager.Config{
		PKCS11: profilemanager.PKCS11Config{ModulePath: "/usr/lib/libeTPkcs11.so"},
	}
	s.restorePKCS11Certificates(config)

	if len(config.ClientCertKeyPairs) != 1 {
		t.Fatalf("certificate not restored: %d pairs", len(config.ClientCertKeyPairs))
	}
}

func TestPKCS11RestoreLeavesOtherProfilesAlone(t *testing.T) {
	s := &Server{}
	s.rememberPKCS11Certificates([]tls.Certificate{{Certificate: [][]byte{{1}}}})

	// No token configured: nothing to restore, and nothing may be invented.
	config := &profilemanager.Config{}
	s.restorePKCS11Certificates(config)
	if config.ClientCertKeyPairs != nil {
		t.Fatal("a certificate was attached to a profile that uses no token")
	}
}

// A certificate already loaded -- from the PIN in the environment, the
// unattended path -- must win over the remembered one.
func TestPKCS11RestoreDoesNotOverwriteALoadedCertificate(t *testing.T) {
	s := &Server{}
	s.rememberPKCS11Certificates([]tls.Certificate{{Certificate: [][]byte{{9, 9}}}})

	atual := []tls.Certificate{{Certificate: [][]byte{{1, 1}}}}
	config := &profilemanager.Config{
		PKCS11:             profilemanager.PKCS11Config{ModulePath: "/usr/lib/libeTPkcs11.so"},
		ClientCertKeyPairs: atual,
	}
	s.restorePKCS11Certificates(config)

	if string(config.ClientCertKeyPairs[0].Certificate[0]) != string(atual[0].Certificate[0]) {
		t.Fatal("the freshly loaded certificate was replaced by the remembered one")
	}
}
