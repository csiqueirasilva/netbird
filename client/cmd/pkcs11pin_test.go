package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestReadPKCS11PinFromEnvironment(t *testing.T) {
	t.Setenv(profilemanager.PinEnvVar, "1234")

	pin, err := readPKCS11Pin(&cobra.Command{})
	if err != nil {
		t.Fatalf("readPKCS11Pin: %v", err)
	}
	if pin != "1234" {
		t.Fatalf("pin = %q, want %q", pin, "1234")
	}
}

// Without a terminal there is nobody to ask, so the error has to point at the
// way out instead of leaving the caller with a failed handshake to debug.
func TestReadPKCS11PinWithoutTerminal(t *testing.T) {
	t.Setenv(profilemanager.PinEnvVar, "")

	// go test runs with stdin detached, which is exactly the case under test.
	_, err := readPKCS11Pin(&cobra.Command{})
	if err == nil {
		t.Fatal("expected an error when there is no terminal and no environment variable")
	}
	if !strings.Contains(err.Error(), profilemanager.PinEnvVar) {
		t.Fatalf("error does not mention %s: %v", profilemanager.PinEnvVar, err)
	}
}

func TestResolvePKCS11ModuleSkipsProfilesWithoutAToken(t *testing.T) {
	pkcs11ModulePath, pkcs11Enabled = "", false

	module, err := resolvePKCS11Module(&cobra.Command{}, "")
	if err != nil {
		t.Fatalf("resolvePKCS11Module: %v", err)
	}
	if module != "" {
		t.Fatalf("module = %q, want empty for a profile that uses no token", module)
	}
}

func TestResolvePKCS11ModulePrefersTheFlag(t *testing.T) {
	pkcs11ModulePath, pkcs11Enabled = "/from/the/flag.so", false
	defer func() { pkcs11ModulePath = "" }()

	module, err := resolvePKCS11Module(&cobra.Command{}, "/from/the/profile.so")
	if err != nil {
		t.Fatalf("resolvePKCS11Module: %v", err)
	}
	if module != "/from/the/flag.so" {
		t.Fatalf("module = %q, want the flag to win", module)
	}
}

// Discovery must not be a requirement: a driver in an unusual place is still
// usable, so a failure has to say where it looked.
func TestSearchedModulePathsIsNotEmpty(t *testing.T) {
	if len(profilemanager.SearchedModulePaths()) == 0 {
		t.Fatal("no PKCS#11 module paths are searched on this platform")
	}
}
