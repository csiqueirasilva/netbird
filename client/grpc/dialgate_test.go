//go:build !js

package grpc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A trava tem de agir ANTES do socket. O endereco usado e' do TEST-NET-3
// (203.0.113.0/24, RFC 5737): nao e roteado para lugar nenhum, entao uma
// tentativa real de conexao ficaria presa ate o timeout. Voltar rapido e' a
// evidencia de que nada foi discado.
func TestTravaRecusaAntesDeAbrirSocket(t *testing.T) {
	t.Cleanup(func() { SetDialGate(nil) })

	recusa := errors.New("token fora do leitor")
	SetDialGate(func() error { return recusa })

	inicio := time.Now()
	conn, err := dialContext(context.Background(), "203.0.113.1:443")
	decorrido := time.Since(inicio)

	if conn != nil {
		_ = conn.Close()
		t.Fatal("abriu conexao apesar da trava fechada")
	}
	if !errors.Is(err, recusa) {
		t.Fatalf("erro inesperado: %v", err)
	}
	if decorrido > time.Second {
		t.Fatalf("levou %v -- lento demais para nao ter discado", decorrido)
	}
}

func TestSemTravaNadaMuda(t *testing.T) {
	SetDialGate(nil)
	if err := checkDialGate(); err != nil {
		t.Fatalf("sem trava instalada nao pode haver erro, deu: %v", err)
	}
}

// Instalar uma trava nova tem de substituir a anterior, e nil tem de remover --
// senao um perfil sem token herdaria a trava de outro e nunca discaria.
func TestTravaSubstituiEremove(t *testing.T) {
	t.Cleanup(func() { SetDialGate(nil) })

	primeira := errors.New("primeira")
	segunda := errors.New("segunda")

	SetDialGate(func() error { return primeira })
	if err := checkDialGate(); !errors.Is(err, primeira) {
		t.Fatalf("esperava a primeira, deu %v", err)
	}

	SetDialGate(func() error { return segunda })
	if err := checkDialGate(); !errors.Is(err, segunda) {
		t.Fatalf("esperava a segunda, deu %v", err)
	}

	SetDialGate(nil)
	if err := checkDialGate(); err != nil {
		t.Fatalf("nil devia remover a trava, deu %v", err)
	}
}
