// Exercises the actual control client across the public-key and Noise phases.
package controlclient

import (
	"context"
	"crypto/x509"
	"encoding/json"
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
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestProxyAppCoordinatorKeyNoiseReuse(t *testing.T) {
	for _, stall := range []bool{false, true} {
		name := "one-connect"
		if stall {
			name = "close-losing-upgrade"
		}
		t.Run(name, func(t *testing.T) { checkProxyKeyNoiseReuse(t, stall) })
	}
}

func checkProxyKeyNoiseReuse(t *testing.T, stall bool) {
	t.Helper()
	const fixtureAuthKey = "test-coordinator-auth"
	serverKey := key.NewMachine()
	var registrations atomic.Int32
	verified := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/machine/register" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var register tailcfg.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&register); err != nil ||
			register.Auth == nil || register.Auth.AuthKey != fixtureAuthKey || register.NodeKey.IsZero() {
			http.Error(w, "unexpected registration", http.StatusBadRequest)
			return
		}
		registrations.Add(1)
		_ = json.NewEncoder(w).Encode(tailcfg.RegisterResponse{MachineAuthorized: true})
	})
	h2 := &http2.Server{}
	upgrade := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, serverKey, nil)
		if err != nil {
			t.Errorf("Noise server handshake failed: %v", err)
			return
		}
		h2.ServeConn(conn, &http2.ServeConnOpts{Context: r.Context(), Handler: verified})
	})
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !stall || r.URL.Path != "/ts2021" {
			http.NotFound(w, r)
			return
		}
		upgrade.ServeHTTP(w, r)
	}))
	t.Cleanup(origin.Close)

	var keyRequests, connects atomic.Int32
	loserClosed := make(chan struct{}, 1)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/key":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.ProtoMajor != 1 {
				http.Error(w, "unexpected key request", http.StatusBadRequest)
				return
			}
			keyRequests.Add(1)
			_ = json.NewEncoder(w).Encode(tailcfg.OverTLSPublicKeyResponse{PublicKey: serverKey.Public()})
		case "/ts2021":
			if stall {
				stallCoordinatorNoise(w, loserClosed)
			} else {
				upgrade.ServeHTTP(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(backend.Close)

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != target.Host {
			http.Error(w, "unexpected coordinator target", http.StatusBadRequest)
			return
		}
		relayCoordinatorConnect(w, backend.Listener.Addr().String(), &connects)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("TS_ORACLE_PROXY_TLS_HOST", target.Hostname())
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_ROUTE", "proxy")
	t.Setenv("TS_ORACLE_PROXY_COORDINATOR_PROXY", proxy.URL)

	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	roots.AddCert(backend.Certificate())
	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	deviceKey := key.NewMachine()
	client, err := NewDirect(Options{
		ServerURL: origin.URL,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return deviceKey, nil
		},
		Dialer:       dialer,
		ExtraRootCAs: roots,
		Bus:          bus,
		Logf:         t.Logf,
		AuthKey:      fixtureAuthKey,
		Hostinfo:     &tailcfg.Hostinfo{BackendLogID: "proxy-coordinator-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	if loginURL, err := client.TryLogin(ctx, LoginDefault); err != nil || loginURL != "" {
		t.Fatalf("coordinator enrollment did not complete: %v", err)
	}
	if stall {
		select {
		case <-loserClosed:
		case <-time.After(time.Second):
			t.Fatal("the losing upgraded connection stayed open")
		}
	}
	if connects.Load() != 1 || keyRequests.Load() != 1 || registrations.Load() != 1 {
		t.Fatalf("expected one CONNECT, key fetch and registration, saw %d, %d and %d",
			connects.Load(), keyRequests.Load(), registrations.Load())
	}
}

func stallCoordinatorNoise(w http.ResponseWriter, closed chan<- struct{}) {
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, err = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " +
		controlhttpcommon.UpgradeHeaderValue + "\r\n\r\n")
	if err != nil || buffered.Flush() != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := buffered.ReadByte(); err != nil {
		if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
			closed <- struct{}{}
		}
	}
}

func relayCoordinatorConnect(w http.ResponseWriter, target string, connects *atomic.Int32) {
	server, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		http.Error(w, "coordinator unavailable", http.StatusBadGateway)
		return
	}
	defer server.Close()
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		return
	}
	connects.Add(1)
	go func() {
		_, _ = io.Copy(server, buffered)
		server.Close()
	}()
	_, _ = io.Copy(client, server)
}
