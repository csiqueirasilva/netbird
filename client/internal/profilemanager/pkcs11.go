package profilemanager

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
)

// PinEnvVar names the environment variable that carries the token PIN when there
// is nobody to ask -- an unattended daemon, CI, a scripted enrolment.
const PinEnvVar = "NB_PKCS11_PIN"

// PKCS11Config points at a hardware token that holds the client certificate's
// private key.
//
// The existing ClientCertPath/ClientCertKeyPath pair calls tls.LoadX509KeyPair,
// which needs the private key on disk. That rules out any token that marks its
// keys non-extractable -- which is the point of buying one. This path keeps the
// key in the token: signing happens on the device, and only the signature
// crosses the PKCS#11 boundary.
//
// Only ModulePath is a setting. It names a driver installed on this machine, so
// it is a property of the machine and belongs in its config. Everything else --
// which token, which certificate, which chain -- is discovered at login, because
// writing it down means writing down a fact that changes when a token is
// replaced or a certificate is reissued, and that goes stale silently.
type PKCS11Config struct {
	// ModulePath is the PKCS#11 shared library, e.g. /usr/lib/libeTPkcs11.so
	// for SafeNet eToken, or opensc-pkcs11.so for OpenSC-driven cards.
	ModulePath string
	// TokenSerial pins the token, for a machine that has several plugged in at
	// once and must not ask. Normally empty: the login flow enumerates what is
	// present and asks when the answer is not obvious.
	TokenSerial string
	// ObjectLabel pins one certificate on the token. Normally empty: the token's
	// certificates are enumerated and the TLS handshake picks, see
	// LoadPKCS11Certificates.
	ObjectLabel string
	// Pin unlocks the token. Never persisted: the config file already holds the
	// WireGuard private key, and writing the PIN beside it collapses two factors
	// into one -- the token stops being "something you have" the moment the PIN
	// is "something on the same disk". The caller supplies it per login.
	Pin string `json:"-"`
}

// IsSet reports whether this profile takes its client certificate from a token.
func (c PKCS11Config) IsSet() bool {
	return c.ModulePath != ""
}

// HasPin reports whether a PIN is available without asking anyone for it.
func (c PKCS11Config) HasPin() bool {
	return c.Pin != "" || os.Getenv(PinEnvVar) != ""
}

// TokenInfo identifies a token the module can currently see.
type TokenInfo struct {
	Serial string
	Label  string
	Model  string
}

// String renders a token the way it is shown to whoever has to pick one.
func (t TokenInfo) String() string {
	return fmt.Sprintf("%s (serial %s, %s)", t.Label, t.Serial, t.Model)
}

// ListTokens reports the tokens plugged in right now.
//
// This is what lets the caller ask which token to use instead of keeping a
// serial number in a config file. It needs no PIN: slot and token information
// are public, and nothing here opens a session.

func (config *Config) UnlockPKCS11(pin, tokenSerial string) error {
	if !config.PKCS11.IsSet() {
		return nil
	}

	cfg := config.PKCS11
	cfg.Pin = pin
	if tokenSerial != "" {
		cfg.TokenSerial = tokenSerial
	}
	if !cfg.HasPin() {
		// Refuse rather than let C_Login run with an empty PIN: a wrong PIN is
		// counted by the token, and these lock themselves after a handful.
		return fmt.Errorf("pkcs11: a PIN is required to unlock the client certificate")
	}

	certificates, err := LoadPKCS11Certificates(cfg)
	if err != nil {
		return err
	}
	config.ClientCertKeyPairs = certificates
	return nil
}

// pkcs11Signer adapts a crypto11 key pair to crypto.Signer.
//
// crypto11 already returns a crypto.Signer, so this only exists to make the
// failure mode explicit: if the token is unplugged mid-session, Sign fails here
// rather than somewhere deep in the TLS stack with an unhelpful message.

func buildChain(leaf *x509.Certificate, authorities []*x509.Certificate) [][]byte {
	chain := [][]byte{leaf.Raw}

	current := leaf
	for range authorities {
		issuer := findIssuer(current, authorities)
		if issuer == nil {
			break
		}
		if bytes.Equal(issuer.RawSubject, issuer.RawIssuer) {
			// A self-signed certificate is a trust anchor. The verifier either
			// already has it or will not trust it for being sent, so stop here.
			break
		}
		chain = append(chain, issuer.Raw)
		current = issuer
	}

	return chain
}

func findIssuer(cert *x509.Certificate, authorities []*x509.Certificate) *x509.Certificate {
	for _, ca := range authorities {
		if ca.Equal(cert) {
			// Self-issued: the top of what the token holds.
			continue
		}
		if !bytes.Equal(cert.RawIssuer, ca.RawSubject) {
			continue
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			continue
		}
		return ca
	}
	return nil
}
