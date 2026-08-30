package android

import (
	"path/filepath"
	"testing"
)

// A profile with no certificate configured must stay that way: this is the case
// of every existing installation, and it has to keep behaving exactly as before.
func TestPreferencesClientCertificateAbsentByDefault(t *testing.T) {
	p := NewPreferences(filepath.Join(t.TempDir(), "netbird.json"))

	cert, err := p.GetClientCertPath()
	if err != nil {
		t.Fatalf("GetClientCertPath: %v", err)
	}
	key, err := p.GetClientCertKeyPath()
	if err != nil {
		t.Fatalf("GetClientCertKeyPath: %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("a certificate was configured out of nowhere: %q %q", cert, key)
	}
}

func TestPreferencesClientCertificateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := NewPreferences(filepath.Join(dir, "netbird.json"))

	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	p.SetClientCertificate(cert, key)

	if err := p.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Read through a fresh Preferences: the values have to come from the
	// profile on disk, not from the instance that set them.
	reloaded := NewPreferences(filepath.Join(dir, "netbird.json"))
	got, err := reloaded.GetClientCertPath()
	if err != nil {
		t.Fatalf("GetClientCertPath: %v", err)
	}
	if got != cert {
		t.Fatalf("certificate path = %q, want %q", got, cert)
	}
	got, err = reloaded.GetClientCertKeyPath()
	if err != nil {
		t.Fatalf("GetClientCertKeyPath: %v", err)
	}
	if got != key {
		t.Fatalf("key path = %q, want %q", got, key)
	}
}

// Withdrawing a credential has to be possible. Without an explicit clear the
// paths would only ever be overwritten, never removed, because apply() takes
// non-empty values only.
func TestPreferencesClientCertificateCanBeRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netbird.json")

	p := NewPreferences(path)
	p.SetClientCertificate(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err := p.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	clearing := NewPreferences(path)
	clearing.ClearClientCertificate()
	if err := clearing.Commit(); err != nil {
		t.Fatalf("Commit after clear: %v", err)
	}

	after := NewPreferences(path)
	cert, err := after.GetClientCertPath()
	if err != nil {
		t.Fatalf("GetClientCertPath: %v", err)
	}
	key, err := after.GetClientCertKeyPath()
	if err != nil {
		t.Fatalf("GetClientCertKeyPath: %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("certificate survived the clear: %q %q", cert, key)
	}
}
