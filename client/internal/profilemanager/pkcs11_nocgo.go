//go:build !cgo

package profilemanager

import (
	"crypto/tls"
	"fmt"
)

// Without cgo there is no PKCS#11: the vendor module is a C library loaded at
// run time, and the binding needs cgo to call it. The mobile client is built
// that way (`gomobile bind` uses CGO_ENABLED=0), so these exist to keep the
// package compiling and fail with a reason, rather than disappearing and
// spreading build tags across every caller.
//
// On a device with no cryptographic hardware the path is a different one
// anyway: ClientCertPath/ClientCertKeyPath, which are files and need no cgo.

const withoutCGO = "pkcs11: this build has no PKCS#11 support (compiled without cgo); " +
	"use a certificate and key file instead"

func LoadPKCS11Certificates(_ PKCS11Config) ([]tls.Certificate, error) {
	return nil, fmt.Errorf("%s", withoutCGO)
}

// ListTokens reports the tokens plugged in right now.
func ListTokens(_ string) ([]TokenInfo, error) {
	return nil, fmt.Errorf("%s", withoutCGO)
}

func listTokens(_ string, _ int) ([]TokenInfo, error) {
	return nil, fmt.Errorf("%s", withoutCGO)
}
