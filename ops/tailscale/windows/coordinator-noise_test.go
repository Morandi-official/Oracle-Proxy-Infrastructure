// Exercises the pinned coordinator transport with the full TLS and Noise stack.
// The server and its one-time keys are local to this test.
package ts2021

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/key"
)

func TestProxyAppCoordinatorDelayedNoise(t *testing.T) {
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_FALLBACK_PROXY", "")
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_IP", "")
	for _, route := range []string{"direct", "proxy"} {
		t.Run(route, func(t *testing.T) { checkDelayedNoise(t, route) })
	}
	t.Run("preferred-proxy-stalls-after-upgrade", checkStalledProxyFallback)
	t.Run("stale-address-uses-current-dns", func(t *testing.T) { checkStalePinFallback(t, false) })
	t.Run("stale-address-uses-configured-proxy", func(t *testing.T) { checkStalePinFallback(t, true) })
}

func checkDelayedNoise(t *testing.T, route string) {
	t.Helper()
	const latency = 13 * time.Second
	server, origin, serverKey := testCoordinator(t, latency)
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_ROUTE", route)

	var proxyUses atomic.Int32
	if route == "proxy" {
		t.Setenv("TS_ORACLE_PROXY_COORDINATOR_PROXY", testCoordinatorProxy(t, origin.Host, origin.Host, &proxyUses))
	}
	started := time.Now()
	verifyCoordinatorNoise(t, server, serverKey, 27*time.Second)
	if time.Since(started) < latency {
		t.Fatal("the Noise connection did not use the delayed HTTPS server")
	}
	if route == "proxy" && proxyUses.Load() == 0 {
		t.Fatal("the preferred proxy was not attempted")
	}
}

func checkStalledProxyFallback(t *testing.T) {
	server, origin, serverKey := testCoordinator(t, 250*time.Millisecond)
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_ROUTE", "proxy")
	upgraded := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	// This route successfully establishes TLS and upgrades HTTP, then
	// stalls before proving possession of the server's Noise key.
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != controlhttpcommon.UpgradeHeaderValue {
			http.Error(w, "unexpected coordinator request", http.StatusBadRequest)
			return
		}
		conn, buffer, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, err = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " +
			controlhttpcommon.UpgradeHeaderValue + "\r\n\r\n")
		if err != nil || buffer.Flush() != nil {
			return
		}
		upgraded <- struct{}{}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = buffer.ReadByte()
		if err != nil {
			if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
				closed <- struct{}{}
			}
		}
	}))
	t.Cleanup(bad.Close)
	var proxyUses atomic.Int32
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_PROXY", testCoordinatorProxy(t, origin.Host, bad.Listener.Addr().String(), &proxyUses))
	verifyCoordinatorNoise(t, server, serverKey, 4*time.Second)
	select {
	case <-upgraded:
	default:
		t.Fatal("preferred proxy never completed the HTTP upgrade")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the losing upgraded connection was left open")
	}
}

func checkStalePinFallback(t *testing.T, useProxy bool) {
	server, origin, serverKey := testCoordinator(t, 0)
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_ROUTE", "direct")
	// The local server only listens on 127.0.0.1. Keep this stale pin
	// away from both the normal resolver and the proxy transport.
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_IP", "127.0.0.2")
	var proxyUses atomic.Int32
	if useProxy {
		t.Setenv("TS_ORACLE_PROXY_COORDINATOR_FALLBACK_PROXY",
			testCoordinatorProxy(t, origin.Host, origin.Host, &proxyUses))
	}
	verifyCoordinatorNoise(t, server, serverKey, 4*time.Second)
	if useProxy && proxyUses.Load() == 0 {
		t.Fatal("the independent configured proxy was not attempted")
	}
}

const coordinatorProof = "verified-noise"

func testCoordinator(t *testing.T, latency time.Duration) (*httptest.Server, *url.URL, key.MachinePrivate) {
	t.Helper()
	serverKey := key.NewMachine()
	server := httptest.NewUnstartedServer(&Upgrader{
		h2srv:        &http2.Server{},
		noiseKeyPriv: serverKey,
		httpBaseConfig: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/verified" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, coordinatorProof)
		})},
	})
	if latency > 0 {
		server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			time.Sleep(latency)
			return nil, nil
		}}
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TS_ORACLE_PROXY_TLS_HOST", origin.Hostname())
	return server, origin, serverKey
}

func verifyCoordinatorNoise(t *testing.T, server *httptest.Server, serverKey key.MachinePrivate, timeout time.Duration) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClient(ClientOpts{
		ServerURL:    server.URL,
		PrivKey:      key.NewMachine(),
		ServerPubKey: serverKey.Public(),
		Dialer:       tsdial.NewDialer(netmon.NewStatic()),
		ExtraRootCAs: roots,
		Logf:         t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/verified", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != coordinatorProof {
		t.Fatalf("expected verified application response, status %d, error %v", response.StatusCode, err)
	}
}

func testCoordinatorProxy(t *testing.T, origin, endpoint string, proxyUses *atomic.Int32) string {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != origin {
			http.Error(w, "unexpected coordinator request", http.StatusForbidden)
			return
		}
		relayCoordinator(w, endpoint, proxyUses)
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}

func relayCoordinator(w http.ResponseWriter, endpoint string, proxyUses *atomic.Int32) {
	backend, err := net.DialTimeout("tcp", endpoint, time.Second)
	if err != nil {
		http.Error(w, "coordinator unavailable", http.StatusBadGateway)
		return
	}
	defer backend.Close()
	client, buffer, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffer.Flush() != nil {
		return
	}
	proxyUses.Add(1)
	go func() {
		_, _ = io.Copy(backend, buffer)
		backend.Close()
	}()
	_, _ = io.Copy(client, backend)
}
