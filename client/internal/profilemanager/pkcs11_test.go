package profilemanager

import "testing"

// Sem token nao da para testar assinatura, mas a validacao de configuracao e o
// texto dos erros sao o que mais confunde quem esta configurando -- e isso da
// para cobrir sem hardware.
func TestPKCS11ConfigIsSet(t *testing.T) {
	casos := []struct {
		nome string
		cfg  PKCS11Config
		quer bool
	}{
		{"vazio", PKCS11Config{}, false},
		{"so modulo", PKCS11Config{ModulePath: "/usr/lib/libeTPkcs11.so"}, false},
		{"modulo e label", PKCS11Config{ModulePath: "/l.so", TokenLabel: "eToken"}, true},
		{"modulo e serial", PKCS11Config{ModulePath: "/l.so", TokenSerial: "02f1ba64"}, true},
		{"so serial", PKCS11Config{TokenSerial: "02f1ba64"}, false},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			if got := c.cfg.IsSet(); got != c.quer {
				t.Fatalf("IsSet() = %v, queria %v", got, c.quer)
			}
		})
	}
}

func TestLoadPKCS11CertificateRejeitaConfigIncompleta(t *testing.T) {
	_, err := LoadPKCS11Certificate(PKCS11Config{ModulePath: "/nao/existe.so"})
	if err == nil {
		t.Fatal("esperava erro para configuracao incompleta")
	}
}
