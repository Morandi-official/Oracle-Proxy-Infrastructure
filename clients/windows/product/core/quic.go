// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"

	"github.com/sagernet/sing-box/log"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
)

const quicType = "oracle-quic"

type quicOptions struct {
	Token       string `json:"token"`
	Certificate string `json:"certificate"`
}
type quicOutbound struct {
	outbound.Adapter
	physical N.Dialer
	options  quicOptions
}

func newQUICOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options quicOptions) (adapter.Outbound, error) {
	if !relayToken.MatchString(options.Token) {
		return nil, errors.New("QUIC_TOKEN_REJECTED")
	}
	if _, err := quicTLS(options.Certificate); err != nil {
		return nil, err
	}
	physical, err := physicalDialer(ctx)
	if err != nil {
		return nil, err
	}
	return &quicOutbound{Adapter: outbound.NewAdapter(quicType, tag, []string{N.NetworkUDP}, nil), physical: physical, options: options}, nil
}
func (r *quicOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkUDP || destination.String() != "152.67.156.100:51820" {
		return nil, errors.New("QUIC_DESTINATION_REJECTED")
	}
	carrier := M.ParseSocksaddr("152.67.156.100:8443")
	socket, err := r.physical.ListenPacket(ctx, carrier)
	if err != nil {
		return nil, err
	}
	return dialQUIC(ctx, socket, carrier.UDPAddr(), r.options.Certificate, r.options.Token)
}
func (r *quicOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("QUIC_PACKET_LISTENER_REFUSED")
}
