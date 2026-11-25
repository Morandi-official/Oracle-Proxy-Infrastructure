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
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/key"
)

func TestProxyAppCoordinatorDelayedNoise(t *testing.T) {
	for _, route := range []string{"direct", "proxy"} {
		t.Run(route, func(t *testing.T) { checkDelayedNoise(t, route) })
	}
}

func checkDelayedNoise(t *testing.T, route string) {
	t.Helper()
	const latency = 13 * time.Second
	const proof = "verified-noise"
	serverKey := key.NewMachine()
	server := httptest.NewUnstartedServer(&Upgrader{
		h2srv:        &http2.Server{},
		noiseKeyPriv: serverKey,
		httpBaseConfig: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/verified" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, proof)
		})},
	})
	server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		time.Sleep(latency)
		return nil, nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)

	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TS_ORACLE_PROXY_TLS_HOST", origin.Hostname())
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_ROUTE", route)
	envknob.SetenvForTest(t, "TS_FORCE_NOISE_443", "true")
	var proxyUses atomic.Int32
	if route == "proxy" {
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Host != origin.Host {
				http.Error(w, "unexpected coordinator request", http.StatusForbidden)
				return
			}
			relayCoordinator(w, origin.Host, &proxyUses)
		}))
		t.Cleanup(proxy.Close)
		t.Setenv("TS_ORACLE_PROXY_COORDINATOR_PROXY", proxy.URL)
	}
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

	ctx, cancel := context.WithTimeout(t.Context(), 27*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/verified", nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != proof ||
		time.Since(started) < latency {
		t.Fatalf("expected verified application response after delayed TLS, status %d, error %v", response.StatusCode, err)
	}
	if route == "proxy" && proxyUses.Load() == 0 {
		t.Fatal("the advertised alternate route did not carry the Noise connection")
	}
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
