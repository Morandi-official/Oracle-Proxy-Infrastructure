//go:build windows && oracle_binding_lab

package tun

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing-tun/internal/winipcfg"
	"github.com/sagernet/sing-tun/internal/wintun"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/windows"
)

// Only the held, restored adapter receives these documentation-only host addresses
// and host routes. No endpoint, DNS change, external peer or default route is involved.
func labRoundTrip(t *testing.T, luid winipcfg.LUID, session wintun.Session, click time.Time) {
	t.Helper()
	local4 := netip.MustParseAddr("192.0.2.41")
	peer4 := netip.MustParseAddr("192.0.2.42")
	local6 := netip.MustParseAddr("2001:db8:6f70::41")
	peer6 := netip.MustParseAddr("2001:db8:6f70::42")
	for _, pair := range [][2]netip.Addr{{local4, peer4}, {local6, peer6}} {
		local, peer := pair[0], pair[1]
		network, nextHop := "udp4", netip.IPv4Unspecified()
		if local.Is6() {
			network, nextHop = "udp6", netip.IPv6Unspecified()
		}
		guid := generateGUIDByDeviceName("OracleProxy")
		row, err := luid.Interface()
		if err != nil || row.InterfaceGUID != *guid || row.Alias() != "OracleProxy" || oraclePreparedAdapter.LUID() != uint64(luid) {
			t.Fatal("LOCAL_PROOF_IDENTITY")
		}
		// Limit changes to the two exact addresses, and undo everything before
		// the existing check for removal of the singly owned adapter.
		host := netip.PrefixFrom(local, local.BitLen())
		target := netip.PrefixFrom(peer, peer.BitLen())
		if err = luid.AddIPAddress(host); err != nil {
			t.Fatalf("LOCAL_PROOF_ADDRESS_%s", network)
		}
		defer func() {
			if err := luid.DeleteIPAddress(host); err != nil {
				t.Errorf("LOCAL_PROOF_ADDRESS_CLEANUP_%s", network)
			}
		}()
		if err = luid.AddRoute(target, nextHop, 1); err != nil {
			t.Fatalf("LOCAL_PROOF_ROUTE_%s", network)
		}
		defer func() {
			if err := luid.DeleteRoute(target, nextHop); err != nil {
				t.Errorf("LOCAL_PROOF_ROUTE_CLEANUP_%s", network)
			}
		}()
		// Connected UDP restricts incoming datagrams to this exact source peer
		// and port. UNICAST_IF also pins egress to the same Windows interface.
		configured := time.Since(click)
		dial := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
			Control: control.BindToInterface(nil, "OracleProxy", int(row.InterfaceIndex))}
		deadline := time.Now().Add(3 * time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		dest := netip.AddrPortFrom(peer, 35979)
		var conn net.Conn
		for {
			conn, err = dial.DialContext(ctx, network, dest.String())
			if err == nil {
				break
			}
			if !errors.Is(err, windows.WSAEADDRNOTAVAIL) || time.Now().After(deadline) {
				t.Fatalf("LOCAL_PROOF_SOCKET_%s", network)
			}
			time.Sleep(2 * time.Millisecond)
		}
		defer conn.Close()
		if err = conn.SetDeadline(deadline); err != nil {
			t.Fatal("LOCAL_PROOF_DEADLINE")
		}
		var nonce [24]byte
		rand.Read(nonce[:])
		started := time.Now()
		if n, e := conn.Write(nonce[:]); e != nil || n != len(nonce) {
			t.Fatalf("LOCAL_PROOF_WRITE_%s", network)
		}
		if !labEchoPacket(session, local, peer, uint16(conn.LocalAddr().(*net.UDPAddr).Port), dest.Port(), nonce[:], deadline) {
			t.Fatalf("LOCAL_PROOF_TUN_ECHO_%s", network)
		}
		var received [32]byte
		n, err := conn.Read(received[:])
		if err != nil || !bytes.Equal(received[:n], nonce[:]) {
			t.Fatalf("LOCAL_PROOF_READ_%s", network)
		}
		now := time.Now()
		t.Logf("BIND_LAB_%s_WIN_SOCKET_ECHO_AT_MS=%d LOCAL_RTT_US=%d CONFIGURED_AT_MS=%d SEND_AT_MS=%d",
			network, now.Sub(click).Milliseconds(), now.Sub(started).Microseconds(), configured.Milliseconds(), started.Sub(click).Milliseconds())
		if now.Sub(started) >= 500*time.Millisecond {
			t.Errorf("LOCAL_ROUND_TRIP_OVER_500MS_%s", network)
		}
	}
}

// Echo exactly one identified socket payload through the same Wintun session.
// Received packets belong to the OS until released; only the reply buffer is edited.
func labEchoPacket(session wintun.Session, local, peer netip.Addr, port, targetPort uint16, nonce []byte, deadline time.Time) bool {
	for time.Now().Before(deadline) {
		p, err := session.ReceivePacket()
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			windows.WaitForSingleObject(session.ReadWaitEvent(), 15)
			continue
		}
		if err != nil {
			return false
		}
		var ip header.Network
		switch header.IPVersion(p) {
		case 4:
			if h := header.IPv4(p); h.IsValid(len(p)) {
				ip = h
			}
		case 6:
			if h := header.IPv6(p); h.IsValid(len(p)) {
				ip = h
			}
		}
		if ip == nil || ip.SourceAddr() != local || ip.DestinationAddr() != peer || ip.TransportProtocol() != header.UDPProtocolNumber ||
			len(ip.Payload()) != header.UDPMinimumSize+len(nonce) {
			session.ReleaseReceivePacket(p)
			continue
		}
		udp := header.UDP(ip.Payload())
		if udp.SourcePort() != port || udp.DestinationPort() != targetPort || int(udp.Length()) != len(udp) || !bytes.Equal(udp.Payload(), nonce) {
			session.ReleaseReceivePacket(p)
			continue
		}
		reply, err := session.AllocateSendPacket(len(p))
		if err != nil {
			session.ReleaseReceivePacket(p)
			return false
		}
		copy(reply, p)
		session.ReleaseReceivePacket(p)
		if local.Is4() {
			ip = header.IPv4(reply)
		} else {
			ip = header.IPv6(reply)
		}
		ip.SetSourceAddr(peer)
		ip.SetDestinationAddr(local)
		if ipv4, ok := ip.(header.IPv4); ok {
			ipv4.SetChecksum(0)
			ipv4.SetChecksum(^ipv4.CalculateChecksum())
		}
		udp = header.UDP(ip.Payload())
		udp.SetSourcePort(targetPort)
		udp.SetDestinationPort(port)
		pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, peer.AsSlice(), local.AsSlice(), udp.Length())
		sum := ^udp.CalculateChecksum(checksum.Checksum(udp.Payload(), pseudo))
		if sum == 0 {
			sum = 0xffff
		}
		udp.SetChecksum(sum)
		session.SendPacket(reply)
		return true
	}
	return false
}
