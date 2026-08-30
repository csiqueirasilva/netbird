package profilemanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Without a token there is no signing to exercise, but the discovery rules and
// the error texts are what actually confuse people setting this up, and those
// need no hardware.
func TestPKCS11ConfigIsSet(t *testing.T) {
	cases := []struct {
		name string
		cfg  PKCS11Config
		want bool
	}{
		{"empty", PKCS11Config{}, false},
		{"module only", PKCS11Config{ModulePath: "/usr/lib/libeTPkcs11.so"}, true},
		{"serial without a module", PKCS11Config{TokenSerial: "02f1ba64"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.IsSet(); got != c.want {
				t.Fatalf("IsSet() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPKCS11ConfigHasPin(t *testing.T) {
	cfg := PKCS11Config{ModulePath: "/l.so"}

	t.Setenv(PinEnvVar, "")
	if cfg.HasPin() {
		t.Fatal("HasPin() = true with no PIN anywhere")
	}

	cfg.Pin = "1234"
	if !cfg.HasPin() {
		t.Fatal("HasPin() = false with an explicit PIN")
	}

	cfg.Pin = ""
	t.Setenv(PinEnvVar, "1234")
	if !cfg.HasPin() {
		t.Fatal("HasPin() = false with the PIN in the environment")
	}
}

func TestUnlockPKCS11IgnoresProfilesWithoutAToken(t *testing.T) {
	config := &Config{}
	if err := config.UnlockPKCS11("", ""); err != nil {
		t.Fatalf("UnlockPKCS11 on a profile with no token: %v", err)
	}
	if config.ClientCertKeyPairs != nil {
		t.Fatal("a certificate was loaded for a profile with no token configured")
	}
}

// An empty PIN must be refused before it reaches C_Login. The token counts a
// wrong PIN, and these lock themselves after a handful of attempts, so an
// accidental empty string must never be spent as one of them.
func TestUnlockPKCS11RefusesEmptyPin(t *testing.T) {
	t.Setenv(PinEnvVar, "")

	config := &Config{PKCS11: PKCS11Config{ModulePath: "/does/not/exist.so"}}
	if err := config.UnlockPKCS11("", ""); err == nil {
		t.Fatal("expected UnlockPKCS11 to refuse an empty PIN")
	}
	if config.ClientCertKeyPairs != nil {
		t.Fatal("a certificate was loaded despite the refusal")
	}
}

// Neither the PIN nor the chosen token may end up in the struct that gets
// serialized into the profile.
func TestUnlockPKCS11KeepsChoicesOutOfTheProfile(t *testing.T) {
	config := &Config{PKCS11: PKCS11Config{ModulePath: "/does/not/exist.so"}}

	// The module path is bogus, so this fails. What matters is what it left
	// behind in the config.
	_ = config.UnlockPKCS11("1234", "02f1ba64")

	if config.PKCS11.Pin != "" {
		t.Fatalf("PIN leaked into the persisted config: %q", config.PKCS11.Pin)
	}
	if config.PKCS11.TokenSerial != "" {
		t.Fatalf("token serial leaked into the persisted config: %q", config.PKCS11.TokenSerial)
	}
}

func TestListTokensWithoutAModule(t *testing.T) {
	if _, err := ListTokens(""); err == nil {
		t.Fatal("expected an error with no module path")
	}
}

// buildChain is what replaced the list of certificate labels that used to be
// written into the profile, so it carries the weight of that decision.
func TestBuildChain(t *testing.T) {
	root, rootKey := makeCert(t, "root", nil, nil, true)
	intermediate, intermediateKey := makeCert(t, "intermediate", root, rootKey, true)
	leaf, _ := makeCert(t, "leaf", intermediate, intermediateKey, false)
	stranger, strangerKey := makeCert(t, "stranger", nil, nil, true)
	unrelated, _ := makeCert(t, "unrelated", stranger, strangerKey, false)

	t.Run("walks up to the intermediate and stops before the root", func(t *testing.T) {
		// The root is deliberately among the candidates: a verifier has to
		// already trust it, so sending it proves nothing, but it must also not
		// break the walk.
		chain := buildChain(leaf, []*x509.Certificate{intermediate, root})
		if len(chain) != 2 {
			t.Fatalf("chain of %d, want leaf + intermediate with the root left out", len(chain))
		}
		if string(chain[0]) != string(leaf.Raw) || string(chain[1]) != string(intermediate.Raw) {
			t.Fatal("chain is not ordered leaf-first")
		}
	})

	t.Run("ignores certificates from another CA", func(t *testing.T) {
		chain := buildChain(leaf, []*x509.Certificate{stranger})
		if len(chain) != 1 {
			t.Fatalf("chain of %d, want the leaf alone", len(chain))
		}
	})

	t.Run("a leaf whose issuer is absent is sent alone", func(t *testing.T) {
		chain := buildChain(unrelated, []*x509.Certificate{intermediate, root})
		if len(chain) != 1 {
			t.Fatalf("chain of %d, want the leaf alone", len(chain))
		}
	})
}

func makeCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key for %s: %v", cn, err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create certificate %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", cn, err)
	}

	return cert, key
}
