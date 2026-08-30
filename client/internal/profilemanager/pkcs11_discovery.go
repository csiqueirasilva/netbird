package profilemanager

import (
	"os"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// probeAttempts is deliberately small: a driver that reports no token during a
// scan is usually a driver for some other device, not one that is still waking
// up, and every attempt is paid once per driver installed.
const probeAttempts = 2

// ModuleCandidate is a PKCS#11 driver found on this machine, with whatever
// tokens it can currently see.
type ModuleCandidate struct {
	Path   string
	Tokens []TokenInfo
}

// knownModulePaths lists where the usual PKCS#11 drivers install themselves.
//
// PKCS#11 is a standard interface, not a product: each vendor ships its own
// library behind it. So this cannot be one path -- it is one path per driver we
// expect to meet, and the list is a convenience, never a requirement. Anything
// missing here is still usable by naming the path explicitly.
func knownModulePaths() []string {
	switch runtime.GOOS {
	case "windows":
		system := os.Getenv("SystemRoot")
		if system == "" {
			system = `C:\Windows`
		}
		programs := os.Getenv("ProgramFiles")
		if programs == "" {
			programs = `C:\Program Files`
		}
		return []string{
			filepath.Join(system, "System32", "eTPKCS11.dll"),                                  // SafeNet / Thales eToken
			filepath.Join(programs, "OpenSC Project", "OpenSC", "pkcs11", "opensc-pkcs11.dll"), // OpenSC
			filepath.Join(programs, "Yubico", "Yubico PIV Tool", "bin", "libykcs11.dll"),       // YubiKey PIV
		}
	case "darwin":
		return []string{
			"/usr/local/lib/libeTPkcs11.dylib",
			"/Library/OpenSC/lib/opensc-pkcs11.so",
			"/usr/local/lib/libykcs11.dylib",
			"/opt/homebrew/lib/libykcs11.dylib",
		}
	default:
		return []string{
			"/usr/lib/libeTPkcs11.so",
			"/usr/lib64/libeTPkcs11.so",
			"/usr/local/lib/libeTPkcs11.so",
			"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
			"/usr/lib64/opensc-pkcs11.so",
			"/usr/lib/opensc-pkcs11.so",
			"/usr/lib/x86_64-linux-gnu/libykcs11.so",
			"/usr/lib64/libykcs11.so",
			"/usr/local/lib/libykcs11.so",
		}
	}
}

// DiscoverModules reports the PKCS#11 drivers installed here that load, each
// with the tokens it can see right now.
//
// A driver that loads but sees no token is still reported: "the driver is
// installed, plug the token in" is a different problem from "no driver here at
// all", and telling them apart is the whole point of looking.
//
// Nothing here needs a PIN or opens a session.
func DiscoverModules() []ModuleCandidate {
	var found []ModuleCandidate

	for _, path := range knownModulePaths() {
		if _, err := os.Stat(path); err != nil {
			continue
		}

		tokens, err := listTokens(path, probeAttempts)
		if err != nil {
			// Present but unusable: a stale install, a 32-bit library on a
			// 64-bit process. Worth a log line, not worth stopping for.
			log.Debugf("pkcs11: %s did not load: %v", path, err)
			continue
		}

		found = append(found, ModuleCandidate{Path: path, Tokens: tokens})
	}

	return found
}

// SearchedModulePaths returns where DiscoverModules looked, so a failure can
// say so instead of leaving the reader guessing.
func SearchedModulePaths() []string {
	return knownModulePaths()
}
