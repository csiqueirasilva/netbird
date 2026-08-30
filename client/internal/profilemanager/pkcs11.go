package profilemanager

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/eclipse-keypont/crypto11"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
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
func ListTokens(modulePath string) ([]TokenInfo, error) {
	return listTokens(modulePath, tokenOpenAttempts)
}

// listTokens takes the attempt count because the two callers want different
// answers to an empty slot list. Asking about a token that is meant to be there
// should wait out the module's asynchronous start-up; probing a driver to see
// whether it is the right one should not, since "no token" is a perfectly good
// answer and there may be several drivers to get through.
func listTokens(modulePath string, attempts int) ([]TokenInfo, error) {
	if modulePath == "" {
		return nil, fmt.Errorf("pkcs11: no module path configured")
	}

	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, fmt.Errorf("pkcs11: could not load module %s", modulePath)
	}
	defer module.Destroy()

	if err := module.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: could not initialize module %s: %w", modulePath, err)
	}
	defer func() {
		if err := module.Finalize(); err != nil {
			log.Debugf("pkcs11: finalizing module: %v", err)
		}
	}()

	slots, err := listSlotsWithRetry(module, attempts)
	if err != nil {
		return nil, err
	}

	tokens := make([]TokenInfo, 0, len(slots))
	for _, slot := range slots {
		info, err := module.GetTokenInfo(slot)
		if err != nil {
			log.Debugf("pkcs11: reading token in slot %d: %v", slot, err)
			continue
		}
		tokens = append(tokens, TokenInfo{
			Serial: info.SerialNumber,
			Label:  info.Label,
			Model:  info.Model,
		})
	}

	return tokens, nil
}

// Some modules populate their slot list asynchronously: SafeNet's eTPKCS11
// spawns a reader-monitor thread during C_Initialize and returns before it has
// finished, so the first C_GetSlotList either reports no slots at all or fails
// with CKR_BUFFER_TOO_SMALL -- the reader appearing between the two calls the
// binding makes to size the buffer and then fill it. A single-shot enumeration
// loses that race in whichever process happens to reach it first; the token is
// there, it just has not been announced yet.
const (
	tokenOpenAttempts = 6
	tokenOpenBackoff  = 500 * time.Millisecond
)

func listSlotsWithRetry(module *pkcs11.Ctx, attempts int) ([]uint, error) {
	var err error
	for i := 0; i < attempts; i++ {
		var slots []uint
		if slots, err = module.GetSlotList(true); err == nil && len(slots) > 0 {
			return slots, nil
		}
		time.Sleep(tokenOpenBackoff)
	}
	if err != nil {
		return nil, fmt.Errorf("pkcs11: listing slots: %w", err)
	}
	return nil, nil
}

func openTokenWithRetry(c11 *crypto11.Config) (*crypto11.Context, error) {
	var err error
	for i := 0; i < tokenOpenAttempts; i++ {
		var ctx *crypto11.Context
		if ctx, err = crypto11.Configure(c11); err == nil {
			return ctx, nil
		}
		if !tokenNotAnnouncedYet(err) {
			return nil, err
		}
		time.Sleep(tokenOpenBackoff)
	}
	return nil, err
}

// tokenNotAnnouncedYet reports whether the failure happened while looking for
// the token, before Configure logged in.
//
// This distinction is the whole point of the function: retrying past the login
// would spend PIN attempts, and these tokens lock themselves after a handful of
// wrong ones. Only the two failures that precede C_Login are retried, and both
// are matched on crypto11's own wrapper text because it exports neither.
func tokenNotAnnouncedYet(err error) bool {
	texto := err.Error()
	return strings.Contains(texto, "could not find PKCS#11 token") ||
		strings.Contains(texto, "failed to list PKCS#11 slots")
}

// UnlockPKCS11 loads the client certificates from the hardware token, using a
// PIN and a token choice made for this login only. It is a no-op when the
// profile does not use a token, so callers do not have to test first.
//
// Neither the PIN nor the chosen serial is written back into config.PKCS11:
// that struct is the one that gets serialized. A PIN next to the WireGuard key
// would stop the token from being a second factor, and a serial written down
// silently outlives the token it names.
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
type pkcs11Signer struct {
	inner   crypto.Signer
	subject string
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.inner.Public() }

func (s *pkcs11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.inner.Sign(rand, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: signing with %q failed (token unplugged or PIN not accepted?): %w", s.subject, err)
	}
	return sig, nil
}

// LoadPKCS11Certificates returns every client certificate the token holds, each
// with its chain, and each backed by a key that never leaves the device.
//
// All of them are returned rather than one, because choosing is the TLS
// handshake's job: the server states which CAs it accepts in its
// CertificateRequest, and crypto/tls presents the certificate that matches. That
// is the same mechanism a browser uses, and it means no label has to be written
// down and kept in sync with whatever the server currently trusts.
//
// Certificates that are themselves CAs are not offered as client certificates --
// a token that doubles as a backup CA holds its own CA certificate, and that is
// not an identity to log in with. They are used to build the chains instead.
func LoadPKCS11Certificates(cfg PKCS11Config) ([]tls.Certificate, error) {
	if !cfg.IsSet() {
		return nil, fmt.Errorf("pkcs11: no module path configured")
	}

	pin := cfg.Pin
	if pin == "" {
		pin = os.Getenv(PinEnvVar)
	}

	c11 := &crypto11.Config{Path: cfg.ModulePath, Pin: pin}
	if cfg.TokenSerial != "" {
		c11.TokenSerial = cfg.TokenSerial
	} else {
		// crypto11 wants exactly one way to select a token. With no serial
		// pinned, take the first slot that has one -- the caller resolved any
		// ambiguity before getting here.
		slot := 0
		c11.SlotNumber = &slot
	}

	ctx, err := openTokenWithRetry(c11)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: could not open token via %s: %w", cfg.ModulePath, err)
	}

	pairs, err := ctx.FindAllPairedCertificates()
	if err != nil {
		return nil, fmt.Errorf("pkcs11: listing certificates on the token: %w", err)
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("pkcs11: the token holds no certificate with a matching private key; " +
			"write the issued certificate to it (pkcs11-tool --write-object ... --type cert)")
	}

	var authorities []*x509.Certificate
	var leaves []tls.Certificate
	seen := map[string]bool{}
	for _, pair := range pairs {
		if pair.Leaf == nil {
			continue
		}
		// A token can hold the same certificate against more than one key
		// object -- ours does, from having been written twice. Offering it
		// twice would work but says the wrong thing in the logs.
		if seen[string(pair.Leaf.Raw)] {
			continue
		}
		seen[string(pair.Leaf.Raw)] = true

		if pair.Leaf.IsCA {
			authorities = append(authorities, pair.Leaf)
			continue
		}
		leaves = append(leaves, pair)
	}

	if cfg.ObjectLabel != "" {
		leaves, err = pinnedLeaf(ctx, cfg.ObjectLabel, leaves)
		if err != nil {
			return nil, err
		}
	}

	if len(leaves) == 0 {
		return nil, fmt.Errorf("pkcs11: the token holds only CA certificates, none usable as a client identity")
	}

	certificates := make([]tls.Certificate, 0, len(leaves))
	for _, leaf := range leaves {
		leaf.Certificate = buildChain(leaf.Leaf, authorities)
		leaf.PrivateKey = &pkcs11Signer{
			inner:   leaf.PrivateKey.(crypto.Signer),
			subject: leaf.Leaf.Subject.String(),
		}
		certificates = append(certificates, leaf)
		log.Infof("pkcs11: offering client certificate %q from the token (chain of %d)",
			leaf.Leaf.Subject, len(leaf.Certificate))
	}

	return certificates, nil
}

// pinnedLeaf narrows the candidates to the one the profile named, for the case
// where a token holds several identities and the choice must not be interactive.
func pinnedLeaf(ctx *crypto11.Context, label string, leaves []tls.Certificate) ([]tls.Certificate, error) {
	wanted, err := ctx.FindCertificate(nil, []byte(label), nil)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: looking up certificate %q: %w", label, err)
	}
	if wanted == nil {
		return nil, fmt.Errorf("pkcs11: no certificate labelled %q on the token", label)
	}
	for _, leaf := range leaves {
		if leaf.Leaf.Equal(wanted) {
			return []tls.Certificate{leaf}, nil
		}
	}
	return nil, fmt.Errorf("pkcs11: the certificate labelled %q has no usable private key on the token", label)
}

// buildChain walks from the leaf up through the CA certificates found on the
// token, so the client presents what the server needs to verify it.
//
// A browser gets away with sending only the leaf because the operating system
// keeps the intermediates; a Go client keeps nothing, so an unsent intermediate
// is a handshake the server refuses with no useful diagnostic. The root is left
// out on purpose: the verifier has to already have it, and sending it proves
// nothing.
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
