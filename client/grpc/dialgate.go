package grpc

import "sync/atomic"

// dialGate, when installed, is asked before every dial attempt.
var dialGate atomic.Pointer[func() error]

// SetDialGate installs a precondition checked before each dial attempt, and nil
// removes it.
//
// WHY THIS EXISTS
// ---------------
// When the client certificate lives on a hardware token and the token is
// unplugged, every handshake fails. gRPC does not give up: it reconnects on its
// own, with backoff, forever. Each of those attempts completes a TCP connection
// and starts a TLS handshake before failing, so the server records a handshake
// error every time. Measured against one deployment: 606 such errors from a
// single workstation in 24 hours, all of them from a client that could not
// possibly succeed because the token was out of the reader.
//
// That is not just noise. On a server that watches its own logs for scanning --
// and one behind mutual TLS has little else to watch -- a client hammering
// failed handshakes looks exactly like something worth blocking, and the
// operator ends up either whitelisting their own address or being banned by
// their own defences. Neither is a good answer; not making the attempt is.
//
// The gate sits at the dialer instead of at the TLS layer on purpose: refusing
// here means no TCP connection is opened at all, so the server sees nothing.
// Refusing during the handshake would be too late -- the connection is already
// established and already logged.
func SetDialGate(gate func() error) {
	if gate == nil {
		dialGate.Store(nil)
		return
	}
	dialGate.Store(&gate)
}

// checkDialGate reports whether a dial may proceed.
func checkDialGate() error {
	if gate := dialGate.Load(); gate != nil {
		return (*gate)()
	}
	return nil
}
