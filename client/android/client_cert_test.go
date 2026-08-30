package android

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestWithDeviceCertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")

	t.Run("no certificate beside the config", func(t *testing.T) {
		got := withDeviceCertificate(profilemanager.ConfigInput{ConfigPath: cfg})
		if got.ClientCertPath != "" || got.ClientCertKeyPath != "" {
			t.Fatalf("paths were set with no files present: %q %q", got.ClientCertPath, got.ClientCertKeyPath)
		}
	})

	t.Run("only half of the pair is ignored", func(t *testing.T) {
		escreve(t, filepath.Join(dir, deviceCertFile), "cert")
		got := withDeviceCertificate(profilemanager.ConfigInput{ConfigPath: cfg})
		if got.ClientCertPath != "" {
			t.Fatal("a certificate without its key was accepted")
		}
	})

	t.Run("both present", func(t *testing.T) {
		escreve(t, filepath.Join(dir, deviceKeyFile), "key")
		got := withDeviceCertificate(profilemanager.ConfigInput{ConfigPath: cfg})
		if got.ClientCertPath != filepath.Join(dir, deviceCertFile) {
			t.Fatalf("certificate path = %q", got.ClientCertPath)
		}
		if got.ClientCertKeyPath != filepath.Join(dir, deviceKeyFile) {
			t.Fatalf("key path = %q", got.ClientCertKeyPath)
		}
	})

	// An empty file is a half-finished copy, not a certificate.
	t.Run("empty files are ignored", func(t *testing.T) {
		vazio := t.TempDir()
		escreve(t, filepath.Join(vazio, deviceCertFile), "")
		escreve(t, filepath.Join(vazio, deviceKeyFile), "")
		got := withDeviceCertificate(profilemanager.ConfigInput{ConfigPath: filepath.Join(vazio, "config.json")})
		if got.ClientCertPath != "" {
			t.Fatal("empty files were accepted")
		}
	})
}

func escreve(t *testing.T, path, conteudo string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(conteudo), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
