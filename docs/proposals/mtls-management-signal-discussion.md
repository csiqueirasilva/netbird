# Client certificates for the Management and Signal connections, with the key in a hardware token

This is a design question before any pull request, following the discussion-first
process. There is working code behind it, in a public fork, but I would rather
agree on the shape than send a diff nobody asked for.

## The problem

On a self-hosted deployment the peer's WireGuard private key is stored in
plaintext in the profile file. The peer is already registered, so Management asks
for nothing else on reconnect. Copy that file to another machine and it connects
as that peer: same key, same identity, same access to whatever the peer's groups
allow. Nothing about that copy is visible as an anomaly, and revoking it means
noticing it first.

The threat model is narrow and mundane: an attacker who can read files as the
user (or as root, or from a backup, or from a disk image) gets a durable network
identity, not just a session. There is no second factor on the tunnel — SSO
happens once, at enrolment, and never again for the life of the peer.

What I want is for the tunnel itself, not only the enrolment, to require
something that cannot be copied.

## What already exists upstream, and why it does not cover this

**PR #2188 ("[client] Mtls support", merged 2024-08-13).** This added a client
certificate to the PKCE token exchange against the IdP. The changed files are
`client/internal/auth/pkce_flow.go`, `client/internal/auth/oauth.go`,
`client/internal/config.go` and the two mobile login shims — the certificate is
presented to the IdP's token endpoint and nowhere else. That secures *enrolment*.
It does not touch the Management or Signal gRPC connections, so a stolen profile
still connects, because a registered peer never repeats the SSO exchange.

The key there also has to come from `tls.LoadX509KeyPair`, i.e. from a file on
disk. That is a real limitation for this use case: if the certificate's key is a
copyable file sitting next to the WireGuard key, the threat model has not moved
much — both are one `cp` away.

**Issue #5364 ("mTLS Auth for Proxy Services", open, feature-request).** I want
to be accurate about this one, because it is adjacent but not the same ask. It
proposes mTLS for the reverse-proxy / Agent Network side: a managed internal CA
in the dashboard, per-user certificate issuance and revocation, and identity
header injection at the proxy edge for apps that cannot do OIDC. It is about
authenticating *clients to published services*, not about the peer's control-plane
connections. It has four supporting comments, one of which asks for the proxy to
read identity off the peer certificate — which is the closest anyone gets to what
is proposed here. As far as I can find there is no open ticket for client
certificates on Management/Signal; if I missed one, point me at it and I will
move this there.

**Issue #4278 ("mTLS certificates broken", closed 2025-12-05)** is worth a
mention only as evidence that the existing mTLS path is easy to break without
anyone noticing: the multi-profile refactor stopped sending the certificate to
the IdP and it was the original contributor who reported it. Whatever is decided
here, that path could use a test.

## The proposal, in three independent parts

These are deliberately separable. Each is defensible on its own and can be
accepted, rejected or reshaped without the others.

### 1. Fix `-androidapi` in `build-android-lib.sh` (netbirdio/android-client)

Unrelated to mTLS, and the smallest thing here. `gomobile bind` defaults to
Android API 16; NDK 27 accepts 21..35, so the bind fails outright with
"unsupported API version 16". One line:

```
CGO_ENABLED=0 gomobile bind \
  -androidapi "${NB_ANDROID_API:-24}" \
  ...
```

Default 24, overridable by environment; build with 26 to match `minSdkVersion`.
This is a build fix, not a feature, and I would send it as a standalone PR to
`netbirdio/android-client` if that is welcome.

### 2. Client certificates on the Management and Signal connections

The dialer built its TLS config with `RootCAs` and nothing else.

- `grpc.CreateConnection` takes the certificates explicitly instead of reading
  them from anywhere global.
- Both gRPC clients gain `WithClientCertificates(certs []tls.Certificate)` in the
  option pattern they already use (`shared/management/client`,
  `shared/signal/client`).
- Every call site passes the profile's certificates: the engine's Management and
  Signal connections, the two in `client/internal/auth`, the daemon's Management
  client, and the URL prober. Missing one would show up as an intermittent
  failure against a gated deployment rather than a clean refusal, which is a bad
  way to find out.
- All candidate certificates are offered; the server states which CAs it accepts
  in its `CertificateRequest` and `crypto/tls` presents whichever matches. That is
  the same selection a browser does, and it means `Config.ClientCertKeyPair`
  becomes `ClientCertKeyPairs` — the handshake wants the candidates, not a
  decision already made for it.

The list is empty unless a profile configures a certificate, and the TLS config
is then byte-for-byte what it is today. No proto change is needed for this part;
no server-side change either — the gating is done by whatever terminates TLS in
front of Management and Signal.

This part alone is enough to bind the tunnel to a certificate. It works with
file-based certificates, which is presumably how most people would use it.

### 3. PKCS#11 on the client, so the key can live in hardware

This is the part I am least sure you want, and the one with a dependency
attached.

- The private key is never read. `tls.Certificate.PrivateKey` is a
  `crypto.Signer` that delegates to the device, so only the signature crosses the
  PKCS#11 boundary. Non-extractable keys are the entire reason to buy a token.
- Nothing is written down that can go stale. The driver is discovered by probing
  the usual install locations for SafeNet's eTPKCS11, OpenSC and Yubico's
  libykcs11, per platform; the token is enumerated at login; the certificate is
  discovered on the token, and the chain is built by walking up through the CA
  certificates found there (self-signed anchors are left out; a verifier that
  does not already have the root will not trust it for being sent). Only the
  driver path that worked is persisted, since that genuinely is a property of the
  machine — and if it later disappears from disk, discovery runs again instead of
  failing. `TokenSerial` and `ObjectLabel` remain optional pins for a host with
  several tokens that must not prompt.
- Two flags: `netbird login --pkcs11` to discover, `--pkcs11-module <path>` to
  name it for an unusual install.
- The PIN is collected by the CLI and sent in the `LoginRequest`, because the
  daemon has no terminal — on Windows it runs in a session that cannot show the
  user anything. It is held in memory for that login and never serialized;
  writing it next to the WireGuard key in the profile would collapse the two
  factors into one. `GetConfigResponse` reports which PKCS#11 module the active
  profile uses so the CLI knows to ask *before* logging in rather than after a
  failure. `NB_PKCS11_PIN` still works for unattended enrolment.
- An empty PIN is refused before it reaches `C_Login`, and the open is retried
  only on the two failures that precede login. These tokens lock themselves after
  a handful of wrong attempts, so nothing retries past `C_Login`.
- The certificate is unlocked once and kept for the session, not just for the
  login. The daemon re-attaches it to each config it loads from disk, because a
  reload cannot restore it (that would need the PIN, which is deliberately not
  kept) and the first gRPC call after a successful login would otherwise go out
  without a certificate.
- The unlock is not conditional on the login method: a setup-key peer reaches
  Management and Signal like any other, so a gated deployment needs the
  certificate there too.
- `gomobile bind` compiles with `CGO_ENABLED=0` and the PKCS#11 module is a C
  library loaded at runtime, so the whole package failed to build for Android.
  The implementation now sits behind a cgo build tag with a stub that returns a
  reason rather than disappearing, so callers need no build tags of their own.
  The config types, the chain builder and the unlock entry point are common to
  both.

On mobile, where there is no command line and no module to enumerate, the
certificate is configured explicitly rather than by convention:

```
Preferences.SetClientCertificate(certPath, keyPath)
Preferences.ClearClientCertificate()
Preferences.GetClientCertPath() / GetClientCertKeyPath()
```

The first version of this looked for `client-cert.pem` beside the profile and
used it if present. That was wrong: a file appearing under a known name would
change the client's TLS identity in silence, and the app could not offer a
picker. Where the files live is the app's decision. Removing a credential needs
an explicit `CleanClientCertificate` input, in the shape the config file already
uses for `CleanNATExternalIPs` and `CleanDNSLabels`, because `apply()` only takes
non-empty values and a credential that can be set but never withdrawn is a defect.

A file-based key on a phone is a bridge, not the goal, so there is also a
`ClientCertificateSigner` interface the app implements — the same shape this
package already uses for `TunAdapter` and `ConnectionListener`. It takes an
already-hashed digest and the name of the algorithm the handshake asked for; the
key never crosses. The public key is taken from the certificate so the two cannot
disagree.

## Compatibility

Nothing changes for anyone who does not configure a certificate:

- `CreateConnection` only sets `Certificates` when the slice is non-empty; with
  no certificate configured, the `tls.Config` is what it is today (`RootCAs` and
  nothing else).
- The PKCS#11 unlock returns immediately for a profile with no token configured
  (`TestUnlockPKCS11IgnoresProfilesWithoutAToken`).
- Config reads no longer touch the token at all when no PIN is available. Before
  that guard, every daemon startup, status query and profile listing spent a
  token round trip and logged a failure. The certificate is loaded on the login
  path only.
- The Android preferences default to no certificate, asserted directly
  (`TestPreferencesClientCertificateAbsentByDefault`).
- The daemon's re-attach touches only the profile that was unlocked and never
  overwrites a certificate already loaded (`TestPKCS11RestoreLeavesOtherProfilesAlone`,
  `TestPKCS11RestoreDoesNotOverwriteALoadedCertificate`).
- The proto changes are additive: three optional fields on `LoginRequest` and one
  string on `GetConfigResponse`. Old clients and old daemons ignore them.
- `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build ./client/android/` succeeds
  with the build tag split; the cgo build and its tests are unchanged.
- The existing file-based `ClientCertPath` / `ClientCertKeyPath` path is
  untouched and remains the default. PKCS#11 is mutually exclusive with it.

Server side there is no change at all: the gating is done by whatever terminates
TLS in front of Management and Signal.

## Questions

These are the actual reason for this post.

1. **Does the split into three make sense to you?** In particular, is part 2
   (client certificates on Management and Signal, file-based keys, no new
   dependency) something you would consider on its own, independently of whether
   PKCS#11 ever lands? It is the small change with most of the security benefit.

2. **How would you want the PIN collected?** Today the CLI prompts and passes it
   in `LoginRequest`, because the daemon is a system service with no terminal —
   on Windows, in a session that cannot prompt at all. That adds a secret to the
   daemon IPC, which I am not thrilled about. Alternatives I considered and did
   not pick: a separate `UnlockToken` RPC (cleaner, but the PIN still crosses the
   same socket), an agent-style helper process, or leaving it to
   `NB_PKCS11_PIN` only (which means writing the PIN where the service manager
   can read it, defeating the point). If you have a preferred shape for
   daemon-side secret prompting, I will build to it.

3. **Would you accept a PKCS#11 dependency behind a cgo build tag?**
   `crypto11` / `miekg/pkcs11` binds the native module and needs cgo. The client
   is already built with `CGO_ENABLED=1` in CI, so the produced binaries do not
   change, and the non-cgo build gets a stub that returns a reason. But it is
   still two new modules in `go.mod`, and AGENTS.md is explicit that dependencies
   are your call, not a contributor's.

4. **Is `Preferences.SetClientCertificate` the API you want on Android?** It
   follows the existing preferences shape, but it is a public SDK surface and the
   app would need a screen for it. If you would rather the certificate came from
   the Android keystore via `ClientCertificateSigner` only, and never from file
   paths, that is a smaller surface and I would drop the path-based half.

5. **Does the discovery behaviour match how you want the client to behave
   generally?** Enumerating drivers and tokens at login, prompting when there is
   more than one, persisting only what worked — that is a deliberate departure
   from "write the path in a config file", and it is the kind of CLI behaviour
   AGENTS.md says gets agreed before it is written.

## What is proven and what is not

Proven, against a real SafeNet eToken 5110 SC:

- The PKCE code exchange completes against an IdP token endpoint that requires a
  client certificate, with the peer registering bound to the user, where an
  unpatched client is refused.
- Discovery from a profile with no PKCS#11 block at all: the driver is found and
  named, the token is found, the client certificate is discovered alongside the
  intermediate CA sharing the token, the chain comes out at two, and the mutually
  authenticated request passes the gate. On a machine with both SafeNet and
  OpenSC installed, OpenSC was correctly passed over for seeing no token, and the
  shorter probe retry took discovery from 6.7s to 2.4s.
- The same on Windows: the eTPKCS11 DLL is found in System32 and loads the
  certificate under Wine. The PIN-handling tests pass on the Windows build under
  Wine.
- The CLI prompt path with the daemon started with no PIN in its environment.
- In production on one small self-hosted installation, with Caddy requiring a
  client certificate in front of `/management.ManagementService/*` and
  `/signalexchange.SignalExchange/*`.

Not proven:

- **YubiKey**: the interface is there and libykcs11 is in the discovery list, but
  I have never run it. On Android specifically, `ClientCertificateSigner` has no
  Java implementation at all — only Go-side tests with a fake signer holding a
  real EC key completing an actual TLS handshake, and a refusing signer failing
  the handshake rather than proceeding without a certificate.
- **macOS**: not tested. Windows was tested under Wine, not on Windows.
- **iOS**: not touched.
- Anything about scale. One deployment, a handful of peers, one token model.
- The upstream server side. Nothing here proposes that Management or Signal
  verify certificates themselves; that is left to the TLS terminator, which may
  or may not be the design you would want.

## Where the code is

Public fork, work in progress, not offered as merge-ready:

- `csiqueirasilva/netbird`, branch `feat/pkcs11-client-cert`
- `csiqueirasilva/android-client`, branch `feat/pkcs11-client-cert`

The netbird branch is 12 commits, about 2100 added lines across 33 files, of
which a good share is tests. It is split by concern rather than squashed, so the
three parts above can be read separately. I am not asking anyone to review it as
it stands — I am asking whether any of the three parts is worth turning into a
proper proposal, and in what shape.
