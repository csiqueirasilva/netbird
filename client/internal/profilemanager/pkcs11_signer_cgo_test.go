//go:build cgo

package profilemanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/miekg/pkcs11"
)

// chaveFalsa stands in for a token key: it signs for real with an in-memory
// ECDSA key, or fails with whatever the test wants, so the recovery path can be
// exercised without a device.
type chaveFalsa struct {
	key *ecdsa.PrivateKey
	err error
}

func (c *chaveFalsa) Public() crypto.PublicKey { return c.key.Public() }

func (c *chaveFalsa) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	return ecdsa.SignASN1(r, c.key, digest)
}

func novoSigner(t *testing.T, morta error) (*pkcs11Signer, *chaveFalsa, *int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gerando chave: %v", err)
	}
	viva := &chaveFalsa{key: key}
	chamadas := 0
	s := &pkcs11Signer{
		subject: "CN=teste",
		inner:   &chaveFalsa{key: key, err: morta},
		reopen: func() (crypto.Signer, error) {
			chamadas++
			return viva, nil
		},
	}
	return s, viva, &chamadas
}

// Quando a sessao morre, assinar tem de reabrir o token e funcionar -- sem isto
// o daemon repete com handle morto para sempre e replugar o token nao muda nada.
func TestSignerReabreQuandoASessaoMorre(t *testing.T) {
	for _, caso := range []struct {
		nome string
		erro error
	}{
		{"erro tipado", pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)},
		// Forma so-texto: nao ha garantia de que o pkcs11.Error chegue
		// unwrappable ate aqui, e uma deteccao que so entende uma das formas
		// falharia em silencio, com sintoma identico ao bug original.
		{"erro so em texto", fmt.Errorf("pkcs11: 0x82: CKR_OBJECT_HANDLE_INVALID")},
		{"dispositivo removido", pkcs11.Error(pkcs11.CKR_DEVICE_REMOVED)},
	} {
		t.Run(caso.nome, func(t *testing.T) {
			s, viva, chamadas := novoSigner(t, caso.erro)
			digest := make([]byte, 32)

			assinatura, err := s.Sign(rand.Reader, digest, crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign devia ter se recuperado, deu: %v", err)
			}
			if *chamadas != 1 {
				t.Fatalf("reopen chamado %d vezes, esperado 1", *chamadas)
			}
			if s.live() != crypto.Signer(viva) {
				t.Fatal("o signer novo nao foi guardado; a proxima assinatura falharia de novo")
			}
			if !ecdsa.VerifyASN1(&viva.key.PublicKey, digest, assinatura) {
				t.Fatal("assinatura invalida")
			}
		})
	}
}

// Erro de PIN NAO pode reabrir: cada tentativa errada e' contada pelo token, que
// se bloqueia depois de poucas. Retry automatico aqui inutilizaria o token.
func TestSignerNaoReabreEmErroDePin(t *testing.T) {
	for _, erro := range []error{
		pkcs11.Error(pkcs11.CKR_PIN_INCORRECT),
		pkcs11.Error(pkcs11.CKR_PIN_LOCKED),
	} {
		s, _, chamadas := novoSigner(t, erro)
		if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
			t.Fatalf("%v devia ter falhado", erro)
		}
		if *chamadas != 0 {
			t.Fatalf("reopen chamado %d vezes para %v, tem de ser 0", *chamadas, erro)
		}
	}
}

// Sem reopen configurado (serial desconhecido), o comportamento tem de ser o de
// hoje: falha clara, nenhuma tentativa de login em token que pode ser o errado.
func TestSignerSemReopenSoFalha(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gerando chave: %v", err)
	}
	s := &pkcs11Signer{
		subject: "CN=teste",
		inner:   &chaveFalsa{key: key, err: pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)},
	}
	if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("devia falhar sem reopen")
	}
}

// Todo handshake em voo falha no mesmo instante quando o token sai. Cada um
// abrindo seu proprio C_Login e' o que precisa NAO acontecer.
func TestSignerReabreUmaVezSoComVariosEmParalelo(t *testing.T) {
	s, _, chamadas := novoSigner(t, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err != nil {
				t.Errorf("Sign concorrente falhou: %v", err)
			}
		}()
	}
	wg.Wait()

	if *chamadas != 1 {
		t.Fatalf("reopen chamado %d vezes, esperado exatamente 1", *chamadas)
	}
}
