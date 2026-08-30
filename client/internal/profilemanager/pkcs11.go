package profilemanager

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/eclipse-keypont/crypto11"
	log "github.com/sirupsen/logrus"
)

// pinEnvVar supplies the token PIN when the caller has no other channel.
const pinEnvVar = "NB_PKCS11_PIN"

// PKCS11Config describes a client certificate whose private key lives in a
// hardware token instead of a file.
//
// The existing ClientCertPath/ClientCertKeyPath pair calls tls.LoadX509KeyPair,
// which needs the private key on disk. That rules out any token that marks its
// keys non-extractable -- which is the point of buying one. This path keeps the
// key in the token: signing happens on the device, and only the signature
// crosses the PKCS#11 boundary.
type PKCS11Config struct {
	// ModulePath is the PKCS#11 shared library, e.g. /usr/lib/libeTPkcs11.so
	// for SafeNet eToken, or opensc-pkcs11.so for OpenSC-driven cards.
	ModulePath string
	// TokenLabel selects the token by label. Optional when TokenSerial is set.
	TokenLabel string
	// TokenSerial selects the token by serial. Prefer this when several tokens
	// share a label -- SafeNet eTokens all report "5XPIN-eToken" by default,
	// and slot order changes on every replug.
	TokenSerial string
	// ObjectLabel is the label of the key pair and certificate to use.
	ObjectLabel string
	// ChainLabels are labels of intermediate certificates to send after the
	// leaf, in order. A TLS client must present the full chain up to (but not
	// including) the trust anchor: browsers get away with sending only the leaf
	// because the OS keeps intermediates, a Go client keeps nothing.
	ChainLabels []string
	// Pin unlocks the token. Never persisted: the config file already holds the
	// WireGuard private key, and writing the PIN beside it collapses two factors
	// into one -- the token stops being "something you have" the moment the PIN
	// is "something on the same disk". The caller supplies it per invocation.
	Pin string `json:"-"`
}

// IsSet reports whether enough was configured to attempt a PKCS#11 login.
func (c PKCS11Config) IsSet() bool {
	return c.ModulePath != "" && (c.TokenLabel != "" || c.TokenSerial != "")
}

// pkcs11Signer adapts a crypto11 key pair to crypto.Signer.
//
// crypto11 already returns a crypto.Signer, so this only exists to keep the
// public certificate alongside it and to make the failure mode explicit: if the
// token is unplugged mid-session, Sign fails here rather than somewhere deep in
// the TLS stack with an unhelpful message.
type pkcs11Signer struct {
	inner crypto.Signer
	label string
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.inner.Public() }

func (s *pkcs11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.inner.Sign(rand, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: signing with %q failed (token unplugged or PIN not accepted?): %w", s.label, err)
	}
	return sig, nil
}

// LoadPKCS11Certificate builds a tls.Certificate whose private key stays in the
// token. The certificate itself is read from the token as well, so a single
// configuration block is enough -- no PEM file to keep in sync with the device.
func LoadPKCS11Certificate(cfg PKCS11Config) (*tls.Certificate, error) {
	if !cfg.IsSet() {
		return nil, fmt.Errorf("pkcs11: incomplete configuration: module path and token label or serial are required")
	}

	pin := cfg.Pin
	if pin == "" {
		// Transient by design: the PIN must not be persisted, and there is no
		// interactive collection yet. An environment variable is the smallest
		// mechanism that keeps it out of the profile file.
		pin = os.Getenv(pinEnvVar)
	}

	c11 := &crypto11.Config{
		Path: cfg.ModulePath,
		Pin:  pin,
	}
	// Serial wins over label: labels are frequently duplicated across tokens
	// from the same vendor, serials are not.
	if cfg.TokenSerial != "" {
		c11.TokenSerial = cfg.TokenSerial
	} else {
		c11.TokenLabel = cfg.TokenLabel
	}

	ctx, err := openTokenWithRetry(c11)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: could not open token via %s: %w", cfg.ModulePath, err)
	}

	signer, err := findSigner(ctx, cfg.ObjectLabel)
	if err != nil {
		return nil, err
	}

	leaf, err := findCertificate(ctx, cfg.ObjectLabel)
	if err != nil {
		return nil, err
	}

	cadeia := [][]byte{leaf.Raw}
	for _, rotulo := range cfg.ChainLabels {
		intermediaria, err := findCertificate(ctx, rotulo)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: chain certificate %q: %w", rotulo, err)
		}
		cadeia = append(cadeia, intermediaria.Raw)
	}

	log.Infof("pkcs11: using client certificate %q from token (subject %q, chain of %d)",
		cfg.ObjectLabel, leaf.Subject, len(cadeia))

	return &tls.Certificate{
		Certificate: cadeia,
		PrivateKey:  &pkcs11Signer{inner: signer, label: cfg.ObjectLabel},
		Leaf:        leaf,
	}, nil
}

// Some modules populate their slot list asynchronously: SafeNet's eTPKCS11
// spawns a reader-monitor thread during C_Initialize and returns before it has
// finished, so the first C_GetSlotList either reports no slots at all or fails
// with CKR_BUFFER_TOO_SMALL -- the reader appearing between the two calls the
// binding makes to size the buffer and then fill it. A single-shot Configure
// loses that race in whichever process happens to reach it first; the token is
// there, it just has not been announced yet.
const (
	tokenOpenAttempts = 6
	tokenOpenBackoff  = 500 * time.Millisecond
)

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

func findSigner(ctx *crypto11.Context, label string) (crypto.Signer, error) {
	if label != "" {
		signer, err := ctx.FindKeyPair(nil, []byte(label))
		if err != nil {
			return nil, fmt.Errorf("pkcs11: looking up key %q: %w", label, err)
		}
		if signer == nil {
			return nil, fmt.Errorf("pkcs11: no key pair labelled %q on the token", label)
		}
		return signer, nil
	}

	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("pkcs11: listing key pairs: %w", err)
	}
	if len(signers) != 1 {
		return nil, fmt.Errorf("pkcs11: token holds %d key pairs; set the object label to pick one", len(signers))
	}
	return signers[0], nil
}

func findCertificate(ctx *crypto11.Context, label string) (*x509.Certificate, error) {
	var (
		cert *x509.Certificate
		err  error
	)
	if label != "" {
		cert, err = ctx.FindCertificate(nil, []byte(label), nil)
	} else {
		cert, err = ctx.FindCertificate(nil, nil, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("pkcs11: looking up certificate %q: %w", label, err)
	}
	if cert == nil {
		return nil, fmt.Errorf("pkcs11: key %q found but no certificate with the same label; "+
			"write the issued certificate to the token (pkcs11-tool --write-object ... --type cert)",
			strings.TrimSpace(label))
	}
	return cert, nil
}
