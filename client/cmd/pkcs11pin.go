package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// collectPKCS11 resolves everything a token-backed login needs and cannot be
// stored: which token, and its PIN.
//
// Neither is collected by the daemon, because the daemon has no terminal: it
// runs as a system service, on Windows in a session that cannot show the user
// anything. So the CLI asks and passes the answers in the login request -- the
// same channel that already carries setup keys -- and the daemon keeps them for
// that login only.
//
// It returns empty strings when the active profile does not use a token.
func collectPKCS11(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, profileName, username string) (pin string, tokenSerial string, module string, err error) {
	configured := ""
	if resp, err := client.GetConfig(ctx, &proto.GetConfigRequest{ProfileName: profileName, Username: username}); err != nil {
		// Not fatal, and deliberately not a prompt: a daemon older than this
		// field answers nothing useful, and most profiles have no token. Let the
		// login proceed and fail on its own terms if a certificate was needed.
		log.Debugf("could not check whether the profile uses a PKCS#11 token: %v", err)
	} else {
		configured = resp.GetPkcs11Module()
	}

	module, err = resolvePKCS11Module(cmd, configured)
	if err != nil || module == "" {
		return "", "", "", err
	}

	if tokenSerial, err = chooseToken(cmd, module); err != nil {
		return "", "", "", err
	}

	if pin, err = readPKCS11Pin(cmd); err != nil {
		return "", "", "", err
	}

	return pin, tokenSerial, module, nil
}

// resolvePKCS11Module decides which PKCS#11 driver to use, and returns an empty
// path when this profile does not use a token at all.
//
// The order is: what the flag says, then what the profile records, then what is
// installed on this machine. The profile's value is checked against the disk
// first, because a driver upgrade can move it and a recorded path that no
// longer exists should send us looking again rather than fail.
func resolvePKCS11Module(cmd *cobra.Command, configured string) (string, error) {
	if pkcs11ModulePath != "" {
		return pkcs11ModulePath, nil
	}

	if configured != "" {
		if _, err := os.Stat(configured); err == nil {
			return configured, nil
		}
		cmd.Printf("The PKCS#11 driver recorded for this profile is gone (%s); looking for another.\n", configured)
	} else if !pkcs11Enabled {
		return "", nil
	}

	return discoverPKCS11Module(cmd)
}

// discoverPKCS11Module looks for an installed driver.
//
// PKCS#11 is a standard interface, not a product: SafeNet, OpenSC and Yubico
// each ship their own library behind it, in their own place. So this probes the
// usual locations and, when that fails, says where it looked -- a path this
// specific is not something to make anyone guess at.
func discoverPKCS11Module(cmd *cobra.Command) (string, error) {
	candidates := profilemanager.DiscoverModules()

	var loaded []profilemanager.ModuleCandidate
	for _, candidate := range candidates {
		if len(candidate.Tokens) > 0 {
			loaded = append(loaded, candidate)
		}
	}

	switch len(loaded) {
	case 1:
		cmd.Printf("Using PKCS#11 driver %s\n", loaded[0].Path)
		return loaded[0].Path, nil
	case 0:
		if len(candidates) > 0 {
			var installed []string
			for _, candidate := range candidates {
				installed = append(installed, candidate.Path)
			}
			return "", fmt.Errorf("a PKCS#11 driver is installed (%s) but sees no token: "+
				"plug in the token that holds the client certificate",
				strings.Join(installed, ", "))
		}
		return "", fmt.Errorf("no PKCS#11 driver found on this machine.\nLooked in:\n  %s\n"+
			"Install the driver for your token -- SafeNet Authentication Client for eToken, "+
			"OpenSC for PIV and IDPrime cards, the YubiKey PIV tool for YubiKey -- "+
			"or name the library with --%s",
			strings.Join(profilemanager.SearchedModulePaths(), "\n  "), pkcs11ModuleFlag)
	}

	cmd.Println("Several PKCS#11 drivers here can see a token:")
	for i, candidate := range loaded {
		cmd.Printf("  %d) %s -- %s\n", i+1, candidate.Path, candidate.Tokens[0])
	}

	choice, err := askChoice(cmd, len(loaded))
	if err != nil {
		return "", err
	}
	return loaded[choice].Path, nil
}

// chooseToken picks among the tokens plugged in right now.
//
// The serial is asked for here instead of being kept in the profile because a
// serial in a config file is a fact that goes stale silently: replace a token,
// or move the profile to another machine, and the login fails pointing at a
// device that is not there. Enumerating costs nothing -- no PIN, no session --
// and answers with what is actually present.
func chooseToken(cmd *cobra.Command, module string) (string, error) {
	tokens, err := profilemanager.ListTokens(module)
	if err != nil {
		return "", err
	}

	switch len(tokens) {
	case 0:
		return "", fmt.Errorf("no hardware token found through %s: plug in the token that holds the client certificate", module)
	case 1:
		cmd.Printf("Using token %s\n", tokens[0])
		return tokens[0].Serial, nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		var seen []string
		for _, t := range tokens {
			seen = append(seen, t.Serial)
		}
		return "", fmt.Errorf("several tokens are plugged in (%s) and there is no terminal to ask on: "+
			"leave one plugged in, or set the token serial in the profile", strings.Join(seen, ", "))
	}

	cmd.Println("Several hardware tokens are plugged in:")
	for i, t := range tokens {
		cmd.Printf("  %d) %s\n", i+1, t)
	}
	choice, err := askChoice(cmd, len(tokens))
	if err != nil {
		return "", err
	}

	return tokens[choice].Serial, nil
}

// askChoice reads a 1-based selection and returns it 0-based.
func askChoice(cmd *cobra.Command, options int) (int, error) {
	cmd.Printf("Which one holds the client certificate? [1-%d]: ", options)

	var answer string
	if _, err := fmt.Fscanln(cmd.InOrStdin(), &answer); err != nil {
		return 0, fmt.Errorf("read choice: %w", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil || choice < 1 || choice > options {
		return 0, fmt.Errorf("%q is not one of 1-%d", answer, options)
	}

	return choice - 1, nil
}

// readPKCS11Pin takes the PIN from the environment, or asks for it.
//
// term.ReadPassword behaves the same on Windows and Unix, so there is one code
// path for both instead of a console handler on one side and termios on the
// other.
func readPKCS11Pin(cmd *cobra.Command) (string, error) {
	if pin := os.Getenv(profilemanager.PinEnvVar); pin != "" {
		return pin, nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("this profile keeps its client certificate in a hardware token, "+
			"so logging in needs the token PIN: run the command from a terminal, or set %s",
			profilemanager.PinEnvVar)
	}

	cmd.Print("Hardware token PIN: ")
	pin, err := term.ReadPassword(fd)
	// The typed PIN left no newline behind, since it was never echoed.
	cmd.Println()
	if err != nil {
		return "", fmt.Errorf("read token PIN: %w", err)
	}
	if len(pin) == 0 {
		return "", fmt.Errorf("no PIN entered")
	}

	return string(pin), nil
}
