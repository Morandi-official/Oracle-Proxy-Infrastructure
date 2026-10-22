// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestNativeUDPPrimaryAndBlockedPrimarySecondary(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(map[bool]string{false: "primary", true: "secondary"}[drop], func(t *testing.T) {
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
				sockets = append(sockets, c)
				go func(i int, s *net.UDPConn) {
					b := make([]byte, 4096)
					for {
						_, a, e := s.ReadFromUDP(b)
						if e != nil {
							return
						}
						if i == 0 && drop {
							continue
						}
						response := make([]byte, 92)
						response[0] = 2
						s.WriteToUDP(response, a)
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
			b := make([]byte, 4096)
			n, e := c.Read(b)
			if e != nil || n != 92 || b[0] != 2 {
				t.Fatal("no handshake response", e)
			}
			want := 0
			if drop {
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
