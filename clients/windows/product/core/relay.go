// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const relayType = "oracle-https"

var relayToken = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type relayOptions struct {
	Token string `json:"token"`
}
type relayOutbound struct {
	outbound.Adapter
	client *http.Client
	token  string
}

var _ adapter.Outbound = (*relayOutbound)(nil)

func newRelayOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options relayOptions) (adapter.Outbound, error) {
	if !relayToken.MatchString(options.Token) {
		return nil, errors.New("RELAY_TOKEN_REJECTED")
	}
	physical, err := dialer.NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "vpn-admin.morandi.dpdns.org:443" {
				return nil, errors.New("RELAY_DESTINATION_REJECTED")
			}
			// Preserve the native physical-interface dialer's loop prevention; TLS
			// still validates the fixed hostname. No proxy, DNS or redirect is used.
			return physical.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("152.67.156.100:443"))
		},
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &relayOutbound{Adapter: outbound.NewAdapter(relayType, tag, []string{N.NetworkUDP}, nil), client: client, token: options.Token}, nil
}

func (r *relayOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkUDP || destination.String() != "152.67.156.100:51820" {
		return nil, errors.New("RELAY_DESTINATION_REJECTED")
	}
	return dialRelay(ctx, r.client, relayURL, r.token)
}
func (r *relayOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("RELAY_PACKET_LISTENER_REFUSED")
}
func (r *relayOutbound) Close() error { r.client.CloseIdleConnections(); return nil }
