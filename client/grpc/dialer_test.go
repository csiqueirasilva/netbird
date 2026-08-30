package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// The dial verifies the server against the system roots, which only
// SSL_CERT_FILE can redirect at a test CA, and only on those platforms.
func requireRedirectableRoots(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skipf("system roots cannot be redirected on %s", runtime.GOOS)
	}
}

func TestCreateConnectionPresentsClientCertificate(t *testing.T) {
	requireRedirectableRoots(t)

	ca, caKey := selfSignedCA(t)
	t.Setenv("SSL_CERT_FILE", writePEM(t, "ca.pem", ca.Raw))

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	seen := make(chan *x509.Certificate, 1)
	addr := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{issue(t, ca, caKey, "127.0.0.1")},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			seen <- cert
			return nil
		},
	})

	client := issue(t, ca, caKey, "peer")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := CreateConnection(ctx, addr, true, "/management", []tls.Certificate{client})
	require.NoError(t, err, "dial with a client certificate")
	t.Cleanup(func() { _ = conn.Close() })

	select {
	case cert := <-seen:
		assert.Equal(t, "peer", cert.Subject.CommonName, "server should see the certificate we offered")
	case <-time.After(5 * time.Second):
		t.Fatal("server never received a client certificate")
	}
}

func TestCreateConnectionWithoutClientCertificateIsRefused(t *testing.T) {
	requireRedirectableRoots(t)

	ca, caKey := selfSignedCA(t)
	t.Setenv("SSL_CERT_FILE", writePEM(t, "ca.pem", ca.Raw))

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	addr := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{issue(t, ca, caKey, "127.0.0.1")},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := CreateConnection(ctx, addr, true, "/management", nil)
	if err == nil {
		_ = conn.Close()
	}
	assert.Error(t, err, "a server requiring a client certificate must refuse a dial without one")
}

func startTLSServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen")

	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	return listener.Addr().String()
}

func selfSignedCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate CA key")

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create CA certificate")

	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err, "parse CA certificate")

	return ca, key
}

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate leaf key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err, "create leaf certificate")

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err, "parse leaf certificate")

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func writePEM(t *testing.T, name string, der []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, encoded, 0o600), "write %s", name)

	return path
}
