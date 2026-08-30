//go:build !cgo

package profilemanager

import (
	"crypto/tls"
	"fmt"
)

// Sem cgo nao ha PKCS#11: o modulo do fabricante e uma biblioteca C carregada em
// tempo de execucao, e o binding precisa de cgo para chama-la. O cliente movel e
// compilado assim (`gomobile bind` usa CGO_ENABLED=0), entao as funcoes existem
// para o pacote compilar e falham dizendo o motivo, em vez de sumirem e
// espalharem build tags por quem as chama.
//
// Num aparelho sem hardware criptografico o caminho e outro de qualquer forma:
// ClientCertPath/ClientCertKeyPath, que sao arquivos e nao precisam de cgo.

const semCGO = "pkcs11: this build has no PKCS#11 support (compiled without cgo); " +
	"use a certificate and key file instead"

func LoadPKCS11Certificates(_ PKCS11Config) ([]tls.Certificate, error) {
	return nil, fmt.Errorf("%s", semCGO)
}

// ListTokens reports the tokens plugged in right now.
func ListTokens(_ string) ([]TokenInfo, error) {
	return nil, fmt.Errorf("%s", semCGO)
}

func listTokens(_ string, _ int) ([]TokenInfo, error) {
	return nil, fmt.Errorf("%s", semCGO)
}
