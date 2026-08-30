package cmd

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// collectPKCS11Pin returns the PIN for the hardware token that holds the client
// certificate, or an empty string when the active profile does not use one.
//
// The PIN is collected here rather than in the daemon because the daemon has no
// terminal: it runs as a system service, on Windows in a session that cannot
// show the user anything at all. So the CLI asks and passes the PIN in the login
// request -- the same channel that already carries setup keys -- and the daemon
// keeps it in memory for that login only.
func collectPKCS11Pin(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, profileName, username string) (string, error) {
	resp, err := client.GetConfig(ctx, &proto.GetConfigRequest{ProfileName: profileName, Username: username})
	if err != nil {
		// Not fatal, and deliberately not a prompt: a daemon older than this
		// field answers nothing useful, and most profiles have no token. Let the
		// login proceed and fail on its own terms if a certificate was needed.
		log.Debugf("could not check whether the profile needs a PKCS#11 PIN: %v", err)
		return "", nil
	}

	if !resp.GetRequiresPkcs11Pin() {
		return "", nil
	}

	return readPKCS11Pin(cmd)
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
