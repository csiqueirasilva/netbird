package profilemanager

import "testing"

// Sem modulo configurado nao ha o que perguntar, e responder "presente" faria o
// daemon discar para sempre com um perfil que nem usa token.
func TestTokenPresentSemModulo(t *testing.T) {
	if TokenPresent("") {
		t.Fatal("sem module path a resposta tem de ser negativa")
	}
}

// Modulo inexistente: nao da para perguntar, entao a resposta segura e' ausente.
// Responder "presente" aqui recriaria exatamente o laco que a trava evita.
func TestTokenPresentModuloInexistente(t *testing.T) {
	if TokenPresent("/caminho/que/nao/existe/libnada.so") {
		t.Fatal("modulo inexistente tem de contar como token ausente")
	}
}
