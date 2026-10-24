// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

type deniedNativeWrite struct{ net.Conn }

func (c deniedNativeWrite) Write([]byte) (int, error) { return 0, errors.New("SYNTHETIC_SEND_DENIED") }

type mtuBoundNativeWrite struct{ net.Conn }

func (c mtuBoundNativeWrite) Write(b []byte) (int, error) {
	if len(b) > 1232 {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: syscall.Errno(10040)}
	}
	return c.Conn.Write(b)
}

func TestNativeUDPRebindKeepsExistingWireGuardSessionData(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	socket, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	c := newNativeConn([]net.Conn{mtuBoundNativeWrite{socket}}, []uint16{8443})
	defer c.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			server.WriteToUDP(buffer[:n], peer)
		}
	}()
	// ClientBind may reconnect its UDP socket while WG retains authenticated
	// session keys. Its next send is encrypted data, not a fresh initiation.
	packet := append([]byte{4, 0, 0, 0}, bytes.Repeat([]byte{17}, 1228)...)
	c.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 20; i++ {
		if _, err := c.Write(packet); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		n, err := c.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("resumed WG data lost: %v", err)
		}
	}
	oversize := append([]byte{4, 0, 0, 0}, make([]byte, 1404)...)
	if _, err := c.Write(oversize); nativeError(err) != 10040 {
		t.Fatal("oversized write error not preserved", err)
	}
	if c.events["NATIVE_UDP_8443_WRITE_ERROR_10040"] != 1 {
		t.Fatal("winning socket error was not counted")
	}
	if _, err := c.Write(append([]byte{1, 0, 0, 0}, make([]byte, 144)...)); err != nil {
		t.Fatal(err)
	}
	if c.attempt != -1 {
		t.Fatal("transport manufactured a new WireGuard handshake")
	}
}

func TestNativeUDPPrimaryAndBlockedPrimarySecondary(t *testing.T) {
	for _, loss := range []int{0, 1, 2, 3, 4} {
		t.Run([]string{"primary", "primary_request_lost", "primary_reply_lost_shared_replay_guard", "late_obsolete_primary_reply", "synchronous_primary_send_denied"}[loss], func(t *testing.T) {
			var replay sync.Mutex
			seen := make(map[string]bool)
			var sockets []net.Conn
			var servers []*net.UDPConn
			for i := 0; i < 2; i++ {
				s, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e != nil {
					t.Fatal(e)
				}
				servers = append(servers, s)
				c, e := net.DialUDP("udp4", nil, s.LocalAddr().(*net.UDPAddr))
				if e != nil {
					t.Fatal(e)
				}
				if i == 0 && loss == 4 {
					sockets = append(sockets, deniedNativeWrite{c})
				} else {
					sockets = append(sockets, c)
				}
				go func(i int, s *net.UDPConn) {
					b := make([]byte, 4096)
					for {
						n, a, e := s.ReadFromUDP(b)
						if e != nil {
							return
						}
						if i == 0 && loss == 1 {
							continue
						}
						// Both aliases reach ONE WG peer. A lost response does
						// not permit an already accepted initiation to be replayed.
						replay.Lock()
						duplicate := seen[string(b[:n])]
						seen[string(b[:n])] = true
						replay.Unlock()
						if duplicate || (i == 0 && loss == 2) {
							continue
						}
						response := make([]byte, 92)
						response[0] = 2
						if loss == 3 {
							delay := 100 * time.Millisecond
							if i == 0 {
								delay = 250 * time.Millisecond
							}
							go func() { time.Sleep(delay); s.WriteToUDP(response, a) }()
						} else {
							s.WriteToUDP(response, a)
						}
					}
				}(i, s)
			}
			defer func() {
				for _, s := range servers {
					s.Close()
				}
			}()
			c := newNativeConn(sockets, []uint16{51820, 443})
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(time.Second))
			packet := append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
			start := time.Now()
			if _, e := c.Write(packet); e != nil {
				t.Fatal(e)
			}
			if loss > 0 && loss < 4 {
				// Model a fresh retry from WG, without changing its real
				// five-second retry timer in the product.
				go func() {
					time.Sleep(50 * time.Millisecond)
					c.Write(packet) // byte-identical retransmit cannot race ports
					time.Sleep(150 * time.Millisecond)
					retry := append([]byte(nil), packet...)
					retry[4] = 1
					c.Write(retry)
				}()
			}
			b := make([]byte, 4096)
			n, e := c.Read(b)
			if e != nil || n != 92 || b[0] != 2 {
				t.Fatal("no handshake response", e)
			}
			want := 0
			if loss > 0 {
				want = 1
			}
			if c.winner != want || time.Since(start) > time.Second {
				t.Fatal("wrong native port", c.winner)
			}
			if !bytes.Equal(packet[:4], []byte{1, 0, 0, 0}) {
				t.Fatal("WireGuard bytes modified")
			}
		})
	}
}
