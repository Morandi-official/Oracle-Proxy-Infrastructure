// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	serviceRegistry "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/wireguard"
)

// Register the configuration surface actually emitted by CoreConfig, including
// every supported carrier. TLS certificate verification remains in each carrier;
// unused ACME/proxy protocols are not initialized merely to build a registry.
func productInbounds() *inbound.Registry {
	r := inbound.NewRegistry()
	tun.RegisterInbound(r)
	socks.RegisterInbound(r)
	return r
}
func productContext() context.Context {
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	outbound.Register[relayOptions](out, relayType, newRelayOutbound)
	outbound.Register[quicOptions](out, quicType, newQUICOutbound)
	outbound.Register[nativeOptions](out, nativeType, newNativeOutbound)
	end := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(end)
	d := dns.NewTransportRegistry()
	transport.RegisterUDP(d)
	transport.RegisterTCP(d)
	transport.RegisterTLS(d)
	transport.RegisterHTTPS(d)
	local.RegisterTransport(d)
	hosts.RegisterTransport(d)
	return box.Context(context.Background(), productInbounds(), out, end, d, serviceRegistry.NewRegistry(), certificate.NewRegistry())
}
