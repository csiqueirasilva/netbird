//go:build cgo

package profilemanager

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-keypont/crypto11"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func ListTokens(modulePath string) ([]TokenInfo, error) {
	return listTokens(modulePath, tokenOpenAttempts)
}

// listTokens takes the attempt count because the two callers want different
// answers to an empty slot list. Asking about a token that is meant to be there
// should wait out the module's asynchronous start-up; probing a driver to see
// whether it is the right one should not, since "no token" is a perfectly good
// answer and there may be several drivers to get through.
func listTokens(modulePath string, attempts int) ([]TokenInfo, error) {
	if modulePath == "" {
		return nil, fmt.Errorf("pkcs11: no module path configured")
	}

	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, fmt.Errorf("pkcs11: could not load module %s", modulePath)
	}
	defer module.Destroy()

	if err := module.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: could not initialize module %s: %w", modulePath, err)
	}
	defer func() {
		if err := module.Finalize(); err != nil {
			log.Debugf("pkcs11: finalizing module: %v", err)
		}
	}()

	slots, err := listSlotsWithRetry(module, attempts)
	if err != nil {
		return nil, err
	}

	tokens := make([]TokenInfo, 0, len(slots))
	for _, slot := range slots {
		info, err := module.GetTokenInfo(slot)
		if err != nil {
			log.Debugf("pkcs11: reading token in slot %d: %v", slot, err)
			continue
		}
		tokens = append(tokens, TokenInfo{
			Serial: info.SerialNumber,
			Label:  info.Label,
			Model:  info.Model,
		})
	}

	return tokens, nil
}

// Some modules populate their slot list asynchronously: SafeNet's eTPKCS11
// spawns a reader-monitor thread during C_Initialize and returns before it has
// finished, so the first C_GetSlotList either reports no slots at all or fails
// with CKR_BUFFER_TOO_SMALL -- the reader appearing between the two calls the
// binding makes to size the buffer and then fill it. A single-shot enumeration
// loses that race in whichever process happens to reach it first; the token is
// there, it just has not been announced yet.
const (
	tokenOpenAttempts = 6
	tokenOpenBackoff  = 500 * time.Millisecond
)

func listSlotsWithRetry(module *pkcs11.Ctx, attempts int) ([]uint, error) {
	var err error
	for i := 0; i < attempts; i++ {
		var slots []uint
		if slots, err = module.GetSlotList(true); err == nil && len(slots) > 0 {
			return slots, nil
		}
		time.Sleep(tokenOpenBackoff)
	}
	if err != nil {
		return nil, fmt.Errorf("pkcs11: listing slots: %w", err)
	}
	return nil, nil
}

func openTokenWithRetry(c11 *crypto11.Config) (*crypto11.Context, error) {
	var err error
	for i := 0; i < tokenOpenAttempts; i++ {
		var ctx *crypto11.Context
		if ctx, err = crypto11.Configure(c11); err == nil {
			return ctx, nil
		}
		if !tokenNotAnnouncedYet(err) {
			return nil, err
		}
		time.Sleep(tokenOpenBackoff)
	}
	return nil, err
}

// tokenNotAnnouncedYet reports whether the failure happened while looking for
// the token, before Configure logged in.
//
// This distinction is the whole point of the function: retrying past the login
// would spend PIN attempts, and these tokens lock themselves after a handful of
// wrong ones. Only the two failures that precede C_Login are retried, and both
// are matched on crypto11's own wrapper text because it exports neither.
func tokenNotAnnouncedYet(err error) bool {
	message := err.Error()
	return strings.Contains(message, "could not find PKCS#11 token") ||
		strings.Contains(message, "failed to list PKCS#11 slots")
}

// UnlockPKCS11 loads the client certificates from the hardware token, using a
// PIN and a token choice made for this login only. It is a no-op when the
// profile does not use a token, so callers do not have to test first.
//
// Neither the PIN nor the chosen serial is written back into config.PKCS11:
// that struct is the one that gets serialized. A PIN next to the WireGuard key
// would stop the token from being a second factor, and a serial written down
// silently outlives the token it names.

type pkcs11Signer struct {
	subject string
	// reopen finds this same certificate's key again on the same token. It is
	// nil when that cannot be done safely -- see makeReopener.
	reopen func() (crypto.Signer, error)

	mu    sync.Mutex
	inner crypto.Signer
}

func (s *pkcs11Signer) live() crypto.Signer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.live().Public() }

func (s *pkcs11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	stale := s.live()
	sig, err := stale.Sign(rand, digest, opts)
	if err == nil {
		return sig, nil
	}
	if s.reopen == nil || !tokenSessionLost(err) {
		return nil, fmt.Errorf("pkcs11: signing with %q failed (token unplugged or PIN not accepted?): %w", s.subject, err)
	}

	fresh, rerr := s.reestablish(stale)
	if rerr != nil {
		return nil, fmt.Errorf("pkcs11: signing with %q failed (%v) and reopening the token did not work: %w", s.subject, err, rerr)
	}
	sig, err = fresh.Sign(rand, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: signing with %q failed even after reopening the token: %w", s.subject, err)
	}
	log.Infof("pkcs11: reopened the session for %q after the token went away", s.subject)
	return sig, nil
}

// reestablish swaps in a live signer, at most once per dead one.
//
// Every in-flight handshake fails at the same instant when the token leaves, so
// without this each one would run its own C_Login against a token that counts
// attempts.
func (s *pkcs11Signer) reestablish(stale crypto.Signer) (crypto.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inner != stale {
		// Someone else already reopened it while this caller was failing.
		return s.inner, nil
	}
	fresh, err := s.reopen()
	if err != nil {
		return nil, err
	}
	s.inner = fresh
	return fresh, nil
}

// tokenSessionLost reports whether the error means the session or the device
// went away -- the only class worth reopening for.
//
// THE PIN FAILURES ARE DELIBERATELY ABSENT. Retrying those spends the token's
// remaining attempts, and these lock themselves after a handful: an automatic
// retry on a wrong PIN would brick the token instead of reporting a problem.
//
// Both shapes are checked because the wrapping is not guaranteed. crypto11 may
// hand back the miekg pkcs11.Error itself, or a message built from it; a check
// that only understood one shape would silently never fire, which is worse than
// not having it -- the symptom would be identical to today's forever-loop.
func tokenSessionLost(err error) bool {
	if err == nil {
		return false
	}

	var code pkcs11.Error
	if errors.As(err, &code) {
		switch code {
		case pkcs11.CKR_OBJECT_HANDLE_INVALID,
			pkcs11.CKR_SESSION_HANDLE_INVALID,
			pkcs11.CKR_SESSION_CLOSED,
			pkcs11.CKR_DEVICE_REMOVED,
			pkcs11.CKR_TOKEN_NOT_PRESENT,
			pkcs11.CKR_DEVICE_ERROR,
			pkcs11.CKR_USER_NOT_LOGGED_IN:
			return true
		default:
			return false
		}
	}

	msg := err.Error()
	for _, name := range []string{
		"CKR_OBJECT_HANDLE_INVALID",
		"CKR_SESSION_HANDLE_INVALID",
		"CKR_SESSION_CLOSED",
		"CKR_DEVICE_REMOVED",
		"CKR_TOKEN_NOT_PRESENT",
		"CKR_DEVICE_ERROR",
		"CKR_USER_NOT_LOGGED_IN",
	} {
		if strings.Contains(msg, name) {
			return true
		}
	}
	return false
}

// makeReopener returns a function that finds one certificate's key again on the
// same token, or nil when that cannot be done safely.
//
// THE SERIAL IS MANDATORY, AND THIS IS NOT CAUTION. Reopening performs a
// C_Login, and a login against the wrong token spends one of THAT token's
// attempts. It has happened here: a command with a fixed serial sent the client
// PIN to the CA token and burned an attempt on it. Doing that automatically, on
// every failed signature, would turn one accident into a loop. With no known
// serial the recovery is given up instead of guessed, which leaves the operator
// exactly where they are today -- rerun the login by hand.
func makeReopener(cfg PKCS11Config, serial string, leafDER []byte) func() (crypto.Signer, error) {
	if serial == "" {
		return nil
	}
	modulePath, pin := cfg.ModulePath, cfg.Pin

	return func() (crypto.Signer, error) {
		unlock := pin
		if unlock == "" {
			// The same variable the unattended path uses. Nothing new is kept:
			// crypto11 holds the PIN for the life of the process either way,
			// and the profile on disk still never sees it.
			unlock = os.Getenv(PinEnvVar)
		}
		if unlock == "" {
			return nil, fmt.Errorf("pkcs11: no PIN available to unlock token %s again", serial)
		}

		ctx, err := openTokenWithRetry(&crypto11.Config{
			Path:        modulePath,
			Pin:         unlock,
			TokenSerial: serial,
		})
		if err != nil {
			return nil, fmt.Errorf("pkcs11: reopening token %s: %w", serial, err)
		}

		pairs, err := ctx.FindAllPairedCertificates()
		if err != nil {
			_ = ctx.Close()
			return nil, fmt.Errorf("pkcs11: listing certificates after reopening token %s: %w", serial, err)
		}
		for _, pair := range pairs {
			if pair.Leaf == nil || !bytes.Equal(pair.Leaf.Raw, leafDER) {
				continue
			}
			signer, ok := pair.PrivateKey.(crypto.Signer)
			if !ok {
				continue
			}
			// The new context stays open: the signer needs it. The one from the
			// dead session is not closed either, because the other certificates
			// from that same load still point at it. Ceiling: one abandoned
			// context per unplug, on a machine that unplugs a few times a day.
			return signer, nil
		}
		_ = ctx.Close()
		return nil, fmt.Errorf("pkcs11: certificate %x is no longer on token %s", leafDER[:8], serial)
	}
}

// LoadPKCS11Certificates returns every client certificate the token holds, each
// with its chain, and each backed by a key that never leaves the device.
//
// All of them are returned rather than one, because choosing is the TLS
// handshake's job: the server states which CAs it accepts in its
// CertificateRequest, and crypto/tls presents the certificate that matches. That
// is the same mechanism a browser uses, and it means no label has to be written
// down and kept in sync with whatever the server currently trusts.
//
// Certificates that are themselves CAs are not offered as client certificates --
// a token that doubles as a backup CA holds its own CA certificate, and that is
// not an identity to log in with. They are used to build the chains instead.
func LoadPKCS11Certificates(cfg PKCS11Config) ([]tls.Certificate, error) {
	if !cfg.IsSet() {
		return nil, fmt.Errorf("pkcs11: no module path configured")
	}

	pin := cfg.Pin
	if pin == "" {
		pin = os.Getenv(PinEnvVar)
	}

	c11 := &crypto11.Config{Path: cfg.ModulePath, Pin: pin}
	if cfg.TokenSerial != "" {
		c11.TokenSerial = cfg.TokenSerial
	} else {
		// crypto11 wants exactly one way to select a token. With no serial
		// pinned, take the first slot that has one -- the caller resolved any
		// ambiguity before getting here.
		slot := 0
		c11.SlotNumber = &slot
	}

	ctx, err := openTokenWithRetry(c11)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: could not open token via %s: %w", cfg.ModulePath, err)
	}

	// Which token this actually is, needed by the reopen path. Only accepted
	// when exactly one token is present: with several plugged in, the open above
	// went by slot number, and mapping that back to a serial would be a guess --
	// and a wrong guess here logs a PIN into the wrong device. See makeReopener.
	serial := cfg.TokenSerial
	if serial == "" {
		if tokens, terr := listTokens(cfg.ModulePath, 1); terr == nil && len(tokens) == 1 {
			serial = tokens[0].Serial
		}
	}

	pairs, err := ctx.FindAllPairedCertificates()
	if err != nil {
		return nil, fmt.Errorf("pkcs11: listing certificates on the token: %w", err)
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("pkcs11: the token holds no certificate with a matching private key; " +
			"write the issued certificate to it (pkcs11-tool --write-object ... --type cert)")
	}

	var authorities []*x509.Certificate
	var leaves []tls.Certificate
	seen := map[string]bool{}
	for _, pair := range pairs {
		if pair.Leaf == nil {
			continue
		}
		// A token can hold the same certificate against more than one key
		// object -- ours does, from having been written twice. Offering it
		// twice would work but says the wrong thing in the logs.
		if seen[string(pair.Leaf.Raw)] {
			continue
		}
		seen[string(pair.Leaf.Raw)] = true

		if pair.Leaf.IsCA {
			authorities = append(authorities, pair.Leaf)
			continue
		}
		leaves = append(leaves, pair)
	}

	if cfg.ObjectLabel != "" {
		leaves, err = pinnedLeaf(ctx, cfg.ObjectLabel, leaves)
		if err != nil {
			return nil, err
		}
	}

	if len(leaves) == 0 {
		return nil, fmt.Errorf("pkcs11: the token holds only CA certificates, none usable as a client identity")
	}

	certificates := make([]tls.Certificate, 0, len(leaves))
	for _, leaf := range leaves {
		leaf.Certificate = buildChain(leaf.Leaf, authorities)
		leaf.PrivateKey = &pkcs11Signer{
			inner:   leaf.PrivateKey.(crypto.Signer),
			subject: leaf.Leaf.Subject.String(),
			reopen:  makeReopener(cfg, serial, leaf.Leaf.Raw),
		}
		certificates = append(certificates, leaf)
		log.Infof("pkcs11: offering client certificate %q from the token (chain of %d)",
			leaf.Leaf.Subject, len(leaf.Certificate))
	}

	return certificates, nil
}

// pinnedLeaf narrows the candidates to the one the profile named, for the case
// where a token holds several identities and the choice must not be interactive.
func pinnedLeaf(ctx *crypto11.Context, label string, leaves []tls.Certificate) ([]tls.Certificate, error) {
	wanted, err := ctx.FindCertificate(nil, []byte(label), nil)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: looking up certificate %q: %w", label, err)
	}
	if wanted == nil {
		return nil, fmt.Errorf("pkcs11: no certificate labelled %q on the token", label)
	}
	for _, leaf := range leaves {
		if leaf.Leaf.Equal(wanted) {
			return []tls.Certificate{leaf}, nil
		}
	}
	return nil, fmt.Errorf("pkcs11: the certificate labelled %q has no usable private key on the token", label)
}

// buildChain walks from the leaf up through the CA certificates found on the
// token, so the client presents what the server needs to verify it.
//
// A browser gets away with sending only the leaf because the operating system
// keeps the intermediates; a Go client keeps nothing, so an unsent intermediate
// is a handshake the server refuses with no useful diagnostic. The root is left
// out on purpose: the verifier has to already have it, and sending it proves
// nothing.
