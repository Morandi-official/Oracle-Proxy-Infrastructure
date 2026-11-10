// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A fresh, bounded, non-resumable HTTP/3 proof travels INSIDE this WireGuard
// endpoint. Never use the physical default dialer or a cached exit result.
func startInitialHTTP3(parent context.Context, dialer N.Dialer) func() {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		var ips [2]string
		var errs [2]error
		var families sync.WaitGroup
		for i, target := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"} {
			families.Add(1)
			go func(i int, target string) { defer families.Done(); ips[i], errs[i] = probeHTTP3(ctx, dialer, target) }(i, target)
		}
		families.Wait()
		if errs[0] == nil && errs[1] == nil {
			// The attested SYSTEM parent independently checks both expected addresses
			// and binds this one-use result to the process/current generation.
			fmt.Fprintln(os.Stderr, "EGRESS_H3_VERIFIED "+ips[0]+" "+ips[1])
		} else {
			fmt.Fprintln(os.Stderr, "EGRESS_H3_UNAVAILABLE")
		}
	}()
	return func() { cancel(); done.Wait() }
}

func traceAddress(body []byte) (string, error) {
	if len(body) > 8192 {
		return "", errors.New("trace too large")
	}
	var result string
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "ip=") {
			continue
		}
		if result != "" {
			return "", errors.New("duplicate trace address")
		}
		ip, err := netip.ParseAddr(strings.TrimSuffix(line[3:], "\r"))
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return "", errors.New("invalid trace address")
		}
		result = ip.String()
	}
	if result == "" {
		return "", errors.New("missing trace address")
	}
	return result, nil
}

// Connected userspace UDP must stay confined to its fixed trace destination.
// quic.Transport owns no physical UDP socket and cannot follow a migration to
// another address through this wrapper.
type fixedProbePacket struct {
	net.Conn
	remote *net.UDPAddr
}

func (p *fixedProbePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, e := p.Read(b)
	return n, p.remote, e
}
func (p *fixedProbePacket) WriteTo(b []byte, remote net.Addr) (int, error) {
	addr, ok := remote.(*net.UDPAddr)
	if !ok || addr.AddrPort() != p.remote.AddrPort() {
		return 0, errors.New("trace destination changed")
	}
	return p.Write(b)
}

func probeHTTP3(ctx context.Context, dialer N.Dialer, target string) (string, error) {
	destination := M.ParseSocksaddr(target)
	connection, err := dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return "", err
	}
	return probeHTTP3Connection(ctx, connection, destination, &tls.Config{ServerName: destination.Addr.String(), MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}})
}
func probeHTTP3Connection(ctx context.Context, connection net.Conn, destination M.Socksaddr, tlsConfig *tls.Config) (string, error) {
	target := destination.String()
	physical := &fixedProbePacket{Conn: connection, remote: net.UDPAddrFromAddrPort(destination.AddrPort())}
	defer physical.Close()
	transport := &quic.Transport{Conn: physical}
	defer transport.Close()
	// Full certificate/hostname validation and fresh TLS Finished; no ticket cache,
	// DialEarly, 0-RTT, InsecureSkipVerify, redirect, cookie or account bearer.
	session, err := transport.Dial(ctx, physical.remote, tlsConfig, &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 2 * time.Second})
	if err != nil {
		return "", err
	}
	defer session.CloseWithError(0, "probe complete")
	clientConn := (&http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 4096}).NewClientConn(session)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+target+"/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	response, err := clientConn.RoundTrip(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("trace HTTP status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil {
		return "", err
	}
	return traceAddress(body)
}
