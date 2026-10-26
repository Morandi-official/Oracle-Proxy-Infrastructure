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
	"strconv"
)

const nativeType = "oracle-native-udp"

type nativeOptions struct {
	Address string   `json:"address"`
	Ports   []uint16 `json:"ports"`
}
type nativeOutbound struct {
	outbound.Adapter
	physical N.Dialer
	ports    []uint16
	address  string
}

func newNativeOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, o nativeOptions) (adapter.Outbound, error) {
	if len(o.Ports) < 1 || len(o.Ports) > 2 || o.Ports[0] == 0 {
		return nil, errors.New("NATIVE_PORTS_REJECTED")
	}
	if len(o.Ports) == 2 && !((o.Ports[0] == 51820 && o.Ports[1] == 443) || (o.Ports[0] == 443 && o.Ports[1] == 51820)) {
		return nil, errors.New("NATIVE_PORTS_REJECTED")
	}
	if o.Address != "" {
		if _, e := ingressAddress(o.Address); e != nil {
			return nil, e
		}
	}
	physical, e := physicalDialer(ctx)
	if e != nil {
		return nil, e
	}
	return &nativeOutbound{Adapter: outbound.NewAdapter(nativeType, tag, []string{N.NetworkUDP}, nil), physical: physical, ports: o.Ports, address: o.Address}, nil
}
func (r *nativeOutbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkUDP || (dest.Port != 51820 && dest.Port != r.ports[0]) {
		return nil, errors.New("NATIVE_DESTINATION_REJECTED")
	}
	var sockets []net.Conn
	var ports []uint16
	for _, port := range r.ports {
		d := dest
		d.Port = port
		if r.address != "" {
			d = M.ParseSocksaddr(net.JoinHostPort(r.address, strconv.Itoa(int(port))))
		}
		var c net.Conn
		var e error
		if d.Addr.IsLoopback() {
			c, e = (&net.Dialer{}).DialContext(ctx, "udp", d.String())
		} else {
			c, e = r.physical.DialContext(ctx, N.NetworkUDP, d)
		}
		if e == nil {
			sockets = append(sockets, c)
			ports = append(ports, port)
		}
	}
	if len(sockets) == 0 {
		return nil, errors.New("NATIVE_CONNECT_FAILED")
	}
	return newNativeConn(sockets, ports), nil
}
func (r *nativeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("NATIVE_LISTENER_REFUSED")
}
