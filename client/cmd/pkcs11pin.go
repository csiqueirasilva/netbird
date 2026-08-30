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
func collectPKCS11(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, profileName, username string) (pin string, tokenSerial string, err error) {
	resp, err := client.GetConfig(ctx, &proto.GetConfigRequest{ProfileName: profileName, Username: username})
	if err != nil {
		// Not fatal, and deliberately not a prompt: a daemon older than this
		// field answers nothing useful, and most profiles have no token. Let the
		// login proceed and fail on its own terms if a certificate was needed.
		log.Debugf("could not check whether the profile uses a PKCS#11 token: %v", err)
		return "", "", nil
	}

	module := resp.GetPkcs11Module()
	if module == "" {
		return "", "", nil
	}

	tokenSerial, err = chooseToken(cmd, module)
	if err != nil {
		return "", "", err
	}

	pin, err = readPKCS11Pin(cmd)
	if err != nil {
		return "", "", err
	}

	return pin, tokenSerial, nil
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
	cmd.Printf("Which one holds the client certificate? [1-%d]: ", len(tokens))

	var answer string
	if _, err := fmt.Fscanln(cmd.InOrStdin(), &answer); err != nil {
		return "", fmt.Errorf("read token choice: %w", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil || choice < 1 || choice > len(tokens) {
		return "", fmt.Errorf("%q is not one of 1-%d", answer, len(tokens))
	}

	return tokens[choice-1].Serial, nil
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
