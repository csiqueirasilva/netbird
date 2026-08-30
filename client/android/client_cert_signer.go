package android

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// ClientCertificateSigner is implemented by the app when the private key lives
// in hardware this library cannot reach: a security key over NFC or USB, or the
// device keystore. The key never leaves it; only signatures cross.
//
// This is the counterpart of the file-based Preferences.SetClientCertificate.
// A file is enough for a key on disk and cannot express a key that has no file,
// which is the entire point of the hardware.
//
// The shape is what gomobile can bind: byte slices, a string, an error.
type ClientCertificateSigner interface {
	// Sign returns a signature over digest, which is ALREADY HASHED. The
	// implementation must not hash it again.
	//
	// algorithm names what the TLS handshake asked for, one of:
	//
	//	ECDSA-SHA256, ECDSA-SHA384, ECDSA-SHA512
	//	RSA-PKCS1-SHA256, RSA-PKCS1-SHA384, RSA-PKCS1-SHA512
	//	RSA-PSS-SHA256, RSA-PSS-SHA384, RSA-PSS-SHA512
	//
	// On Android the ECDSA cases map to Signature "NONEwithECDSA", which takes
	// the digest as-is. The PKCS#1 cases need the DigestInfo prefix that
	// "NONEwithRSA" does not add; a PIV applet usually wants it, the device
	// keystore's "SHA256withRSA" does its own hashing and cannot be fed a
	// digest. Getting that wrong produces a signature the server rejects with a
	// generic handshake failure, so it is spelled out here.
	//
	// An implementation that cannot produce the requested algorithm must return
	// an error rather than a signature of another kind.
	Sign(digest []byte, algorithm string) ([]byte, error)
}

// hardwareSigner adapts ClientCertificateSigner to crypto.Signer.
//
// The public key comes from the certificate rather than from the app: the
// certificate has to carry it anyway, and asking twice invites the two to
// disagree.
type hardwareSigner struct {
	public crypto.PublicKey
	signer ClientCertificateSigner
}

func (s *hardwareSigner) Public() crypto.PublicKey { return s.public }

func (s *hardwareSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algorithm, err := signatureAlgorithm(s.public, opts)
	if err != nil {
		return nil, err
	}

	signature, err := s.signer.Sign(digest, algorithm)
	if err != nil {
		return nil, fmt.Errorf("hardware signer refused to sign with %s: %w", algorithm, err)
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("hardware signer returned an empty signature for %s", algorithm)
	}
	return signature, nil
}

func signatureAlgorithm(public crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	var hash string
	switch opts.HashFunc() {
	case crypto.SHA256:
		hash = "SHA256"
	case crypto.SHA384:
		hash = "SHA384"
	case crypto.SHA512:
		hash = "SHA512"
	default:
		return "", fmt.Errorf("unsupported hash %s for a hardware key", opts.HashFunc())
	}

	switch public.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA-" + hash, nil
	case *rsa.PublicKey:
		if _, pss := opts.(*rsa.PSSOptions); pss {
			return "RSA-PSS-" + hash, nil
		}
		return "RSA-PKCS1-" + hash, nil
	default:
		return "", fmt.Errorf("unsupported key type %T for a hardware key", public)
	}
}

func certificateFromPEM(chainPEM []byte) (*tls.Certificate, error) {
	certificate := &tls.Certificate{}
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate.Certificate = append(certificate.Certificate, block.Bytes)
	}

	if len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found in the PEM given")
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse the leaf certificate: %w", err)
	}
	certificate.Leaf = leaf

	return certificate, nil
}
