// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func testPacket() []byte { return append([]byte{1, 0, 0, 0}, bytes.Repeat([]byte{'x'}, 144)...) }
func TestRelayTLSPacketBoundariesAndClose(t *testing.T) {
	token := strings.Repeat("A", 43)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Cookie") != "" {
			t.Error("credential envelope changed")
			w.WriteHeader(401)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{relayProtocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			kind, b, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if err = conn.Write(r.Context(), kind, b); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	conn, err := dialRelay(context.Background(), server.Client(), server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		packet := testPacket()
		packet[10] = byte(i)
		if _, err = conn.Write(packet); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		n, readErr := conn.Read(buffer)
		if readErr != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatal("packet boundary lost", readErr)
		}
	}
	if _, err = conn.Write([]byte("arbitrary proxy request")); err == nil {
		t.Fatal("invalid frame accepted")
	}
	ended := make(chan struct{})
	go func() { defer close(ended); conn.Read(make([]byte, 4096)) }()
	conn.Close()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("close did not unblock packet reader")
	}
}
func TestRelayRejectsUntrustedTLSAndWrongProtocol(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err == nil {
			defer conn.CloseNow()
			conn.Read(r.Context())
		}
	}))
	defer server.Close()
	if conn, err := dialRelay(context.Background(), http.DefaultClient, server.URL, strings.Repeat("A", 43)); err == nil {
		conn.Close()
		t.Fatal("untrusted TLS accepted")
	}
	if conn, err := dialRelay(context.Background(), server.Client(), server.URL, strings.Repeat("A", 43)); err == nil {
		conn.Close()
		t.Fatal("missing protocol accepted")
	}
}
func TestRelayPacketShapes(t *testing.T) {
	if !validPacket(testPacket()) {
		t.Fatal("valid handshake refused")
	}
	for _, b := range [][]byte{nil, {1, 0, 0, 0}, {4, 0, 0, 0}, append([]byte{1, 1, 0, 0}, bytes.Repeat([]byte{'x'}, 144)...), append([]byte{4, 0, 0, 0}, make([]byte, 4096)...)} {
		if validPacket(b) {
			t.Fatal("invalid packet accepted")
		}
	}
}
func TestReadDeadlineInterruptsAnExistingRead(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{relayProtocol}})
		if err == nil {
			defer conn.CloseNow()
			conn.Read(r.Context())
		}
	}))
	defer server.Close()
	conn, err := dialRelay(context.Background(), server.Client(), server.URL, strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	result := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 4096)); result <- err }()
	time.Sleep(10 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("wrong timeout result", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt pending read")
	}
}
