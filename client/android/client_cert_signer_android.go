//go:build android

package android

import (
	"crypto/tls"
	"fmt"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// SetClientCertificateSigner presents a certificate whose private key stays in
// hardware. chainPEM is the leaf followed by any intermediates.
//
// It is not persisted, and cannot be: the signer is a live object owned by the
// app. Call it again after a restart, before Run.
func (c *Client) SetClientCertificateSigner(chainPEM []byte, signer ClientCertificateSigner) error {
	if signer == nil {
		return fmt.Errorf("no signer given")
	}

	certificate, err := certificateFromPEM(chainPEM)
	if err != nil {
		return err
	}
	certificate.PrivateKey = &hardwareSigner{public: certificate.Leaf.PublicKey, signer: signer}

	c.stateMu.Lock()
	c.clientCert = certificate
	c.stateMu.Unlock()

	return nil
}

// ClearClientCertificateSigner drops a certificate installed by
// SetClientCertificateSigner.
func (c *Client) ClearClientCertificateSigner() {
	c.stateMu.Lock()
	c.clientCert = nil
	c.stateMu.Unlock()
}

// attachClientCertificate puts an installed hardware certificate on a config
// that has just been read.
//
// Mirrors what the daemon does for PKCS#11: the config comes from disk and can
// carry file paths, never a live signer, so whatever holds the signer has to put
// it back on every load.
func (c *Client) attachClientCertificate(config *profilemanager.Config) {
	if config == nil || len(config.ClientCertKeyPairs) > 0 {
		return
	}

	c.stateMu.RLock()
	certificate := c.clientCert
	c.stateMu.RUnlock()

	if certificate != nil {
		config.ClientCertKeyPairs = []tls.Certificate{*certificate}
	}
}
