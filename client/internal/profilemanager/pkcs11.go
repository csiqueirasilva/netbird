package profilemanager

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"strings"

	"github.com/eclipse-keypont/crypto11"
	log "github.com/sirupsen/logrus"
)

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
	// Pin unlocks the token. Empty means the caller supplies it another way.
	Pin string
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

	c11 := &crypto11.Config{
		Path: cfg.ModulePath,
		Pin:  cfg.Pin,
	}
	// Serial wins over label: labels are frequently duplicated across tokens
	// from the same vendor, serials are not.
	if cfg.TokenSerial != "" {
		c11.TokenSerial = cfg.TokenSerial
	} else {
		c11.TokenLabel = cfg.TokenLabel
	}

	ctx, err := crypto11.Configure(c11)
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

	log.Infof("pkcs11: using client certificate %q from token (subject %q)", cfg.ObjectLabel, leaf.Subject)

	return &tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  &pkcs11Signer{inner: signer, label: cfg.ObjectLabel},
		Leaf:        leaf,
	}, nil
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
