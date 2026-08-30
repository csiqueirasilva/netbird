package android

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Nomes procurados ao lado do arquivo de configuracao.
const (
	deviceCertFile = "client-cert.pem"
	deviceKeyFile  = "client-key.pem"
)

// withDeviceCertificate points the config at a client certificate when one is
// present beside it.
//
// On desktop the certificate is chosen by flag or by hardware discovery. Neither
// exists here: this package is a library called from the app, with no command
// line and no PKCS#11 module to enumerate. So the convention is the file itself
// -- drop the certificate and its key next to the profile and the client will
// present them.
//
// The certificate file may hold the intermediates after the leaf;
// tls.LoadX509KeyPair reads every PEM block, so the whole chain is offered. That
// matters against a server that trusts the root and not the intermediate, which
// is the usual arrangement.
//
// The key here is a plain file, not a token. That is the honest limit of a phone
// without a security key: whoever reads the file has the identity. It is a
// bridge until the hardware exists, not a replacement for it.
func withDeviceCertificate(in profilemanager.ConfigInput) profilemanager.ConfigInput {
	if in.ConfigPath == "" {
		return in
	}

	dir := filepath.Dir(in.ConfigPath)
	cert := filepath.Join(dir, deviceCertFile)
	key := filepath.Join(dir, deviceKeyFile)

	if !fileReadable(cert) || !fileReadable(key) {
		return in
	}

	log.Infof("using client certificate from %s", cert)
	in.ClientCertPath = cert
	in.ClientCertKeyPath = key
	return in
}

func fileReadable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}
