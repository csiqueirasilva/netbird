package profilemanager

import "testing"

// Without a token there is no signing to exercise, but the configuration rules
// and the error texts are what actually confuse people setting this up, and
// those need no hardware.
func TestPKCS11ConfigIsSet(t *testing.T) {
	cases := []struct {
		name string
		cfg  PKCS11Config
		want bool
	}{
		{"empty", PKCS11Config{}, false},
		{"module only", PKCS11Config{ModulePath: "/usr/lib/libeTPkcs11.so"}, false},
		{"module and label", PKCS11Config{ModulePath: "/l.so", TokenLabel: "eToken"}, true},
		{"module and serial", PKCS11Config{ModulePath: "/l.so", TokenSerial: "02f1ba64"}, true},
		{"serial only", PKCS11Config{TokenSerial: "02f1ba64"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.IsSet(); got != c.want {
				t.Fatalf("IsSet() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestLoadPKCS11CertificateRejectsIncompleteConfig(t *testing.T) {
	_, err := LoadPKCS11Certificate(PKCS11Config{ModulePath: "/does/not/exist.so"})
	if err == nil {
		t.Fatal("expected an error for an incomplete configuration")
	}
}

func TestPKCS11ConfigHasPin(t *testing.T) {
	cfg := PKCS11Config{ModulePath: "/l.so", TokenSerial: "02f1ba64"}

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
	if err := config.UnlockPKCS11(""); err != nil {
		t.Fatalf("UnlockPKCS11 on a profile with no token: %v", err)
	}
	if config.ClientCertKeyPair != nil {
		t.Fatal("a certificate was loaded for a profile with no token configured")
	}
}

// An empty PIN must be refused before it reaches C_Login. The token counts a
// wrong PIN, and these lock themselves after a handful of attempts, so an
// accidental empty string must never be spent as one of them.
func TestUnlockPKCS11RefusesEmptyPin(t *testing.T) {
	t.Setenv(PinEnvVar, "")

	config := &Config{PKCS11: PKCS11Config{ModulePath: "/does/not/exist.so", TokenSerial: "02f1ba64"}}
	err := config.UnlockPKCS11("")
	if err == nil {
		t.Fatal("expected UnlockPKCS11 to refuse an empty PIN")
	}
	if config.ClientCertKeyPair != nil {
		t.Fatal("a certificate was loaded despite the refusal")
	}
}

// Reading a config must not fail just because the token is locked: the daemon
// reads it on paths that have nobody to ask for a PIN.
func TestUnlockPKCS11KeepsThePinOutOfTheProfile(t *testing.T) {
	config := &Config{PKCS11: PKCS11Config{ModulePath: "/does/not/exist.so", TokenSerial: "02f1ba64"}}

	// The module path is bogus, so this fails -- what matters is where the PIN
	// ended up, since PKCS11 is the struct that gets serialized.
	_ = config.UnlockPKCS11("1234")

	if config.PKCS11.Pin != "" {
		t.Fatalf("PIN leaked into the persisted config: %q", config.PKCS11.Pin)
	}
}
