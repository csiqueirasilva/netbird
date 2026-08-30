//go:build pkcs11hw

package profilemanager

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Exercita a assinatura NO TOKEN de verdade, contra um servidor que exige mTLS.
// Fica atras da tag `pkcs11hw` porque depende de hardware plugado.
//
//	go test -tags pkcs11hw ./client/internal/profilemanager/ -run PKCS11Hardware -v
//
// Variaveis: NB_PKCS11_MODULE, NB_PKCS11_SERIAL, NB_PKCS11_LABEL, NB_PKCS11_PIN,
//            NB_PKCS11_URL (endpoint protegido por client cert)
func chainLabels() []string {
	if v := os.Getenv("NB_PKCS11_CHAIN"); v != "" {
		return strings.Split(v, ",")
	}
	return nil
}

func TestPKCS11HardwareHandshake(t *testing.T) {
	cfg := PKCS11Config{
		ModulePath:  os.Getenv("NB_PKCS11_MODULE"),
		TokenSerial: os.Getenv("NB_PKCS11_SERIAL"),
		ObjectLabel: os.Getenv("NB_PKCS11_LABEL"),
		ChainLabels: chainLabels(),
		Pin:         os.Getenv("NB_PKCS11_PIN"),
	}
	if !cfg.IsSet() {
		t.Skip("NB_PKCS11_MODULE e NB_PKCS11_SERIAL nao definidos")
	}

	cert, err := LoadPKCS11Certificate(cfg)
	if err != nil {
		t.Fatalf("carregar certificado do token: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("certificado sem Leaf preenchido")
	}
	t.Logf("certificado do token: subject=%q", cert.Leaf.Subject)

	url := os.Getenv("NB_PKCS11_URL")
	if url == "" {
		t.Skip("NB_PKCS11_URL nao definido")
	}

	cliente := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*cert},
				RootCAs:      x509.NewCertPool(), // preenchido abaixo se houver CA
			},
		},
	}
	// O servidor usa cert publico (Let's Encrypt); usar o pool do sistema.
	cliente.Transport.(*http.Transport).TLSClientConfig.RootCAs = nil

	resp, err := cliente.Get(url)
	if err != nil {
		t.Fatalf("handshake com o certificado do token falhou: %v", err)
	}
	defer resp.Body.Close()

	// 403 = o portao do Caddy nao aceitou o certificado (ou nao houve certificado).
	// Qualquer outra coisa significa que a requisicao ATRAVESSOU o portao.
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("portao recusou: HTTP 403 -- o certificado do token nao foi aceito")
	}
	t.Logf("atravessou o portao: HTTP %d (403 seria recusa)", resp.StatusCode)
}
