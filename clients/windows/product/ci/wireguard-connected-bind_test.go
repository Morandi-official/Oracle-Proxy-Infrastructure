// Compiled against the vendored WireGuard endpoint in disposable CI.
package wireguard

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	wgconn "github.com/sagernet/wireguard-go/conn"
)

type oracleBindDialer struct {
	N.Dialer
	socket net.Conn
}

func (d oracleBindDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.socket, nil
}

func oracleBoundUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOracleConnectedWireGuardBind(t *testing.T) {
	server := oracleBoundUDP(t)
	target := server.LocalAddr().(*net.UDPAddr)
	socket, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	if err := socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The native port selector may change its reported address after the dial.
	pinned := &oracleReportedRemote{Conn: socket, address: target}
	// The configured WG port and the actual fixed/adaptive carrier can differ.
	bind := NewClientBind(context.Background(), nil, oracleBindDialer{socket: pinned}, true, netip.MustParseAddrPort("192.0.2.2:51820"), [3]uint8{1, 2, 3})
	readers, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bind.Close() })

	// Even when WG supplies a different endpoint, a connected carrier writes
	// to the socket opened for that peer, as it did before the change.
	other := remoteEndpoint(netip.MustParseAddrPort("192.0.2.1:51820"))
	sent := []byte{0xff, 4, 0, 0, 0, 10, 11}
	if err := bind.Send([][]byte{sent}, other, 1); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1280)
	n, from, err := server.ReadFromUDP(buffer)
	if err != nil || !bytes.Equal(buffer[:n], []byte{4, 1, 2, 3, 10, 11}) {
		t.Fatal("connected write", n, err)
	}
	pinned.address = &net.UDPAddr{IP: target.IP, Port: 1}
	reply := []byte{4, 7, 8, 9, 12, 13}
	if _, err := server.WriteToUDP(reply, from); err != nil {
		t.Fatal(err)
	}
	sizes, endpoints := make([]int, 1), make([]wgconn.Endpoint, 1)
	count, err := readers[0]([][]byte{buffer}, sizes, endpoints)
	if err != nil || count != 1 || sizes[0] != len(reply) || endpoints[0].DstToString() != target.String() ||
		!bytes.Equal(buffer[:sizes[0]], []byte{4, 0, 0, 0, 12, 13}) {
		t.Fatal("connected read", count, err, endpoints)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := socket.Write(reply); err == nil {
		t.Fatal("connected socket left open")
	}
}

type oracleReportedRemote struct {
	net.Conn
	address *net.UDPAddr
}

func (s *oracleReportedRemote) RemoteAddr() net.Addr { return s.address }

func TestOracleUnconnectedWireGuardBindKeepsSources(t *testing.T) {
	socket := oracleBoundUDP(t)
	w := &wireConn{PacketConn: socket, done: make(chan struct{})}
	t.Cleanup(func() { w.Close() })
	for _, peer := range []*net.UDPConn{oracleBoundUDP(t), oracleBoundUDP(t)} {
		if _, err := peer.WriteToUDP([]byte{1, 2}, socket.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 8)
		n, ep, err := w.readEndpoint(b)
		if err != nil || n != 2 || ep.DstToString() != peer.LocalAddr().String() {
			t.Fatal("packet source", ep, err)
		}
		if _, err = w.WriteToUDPAddrPort([]byte{3, 4}, netip.AddrPort(ep.(remoteEndpoint))); err != nil {
			t.Fatal(err)
		}
		n, _, err = peer.ReadFromUDP(b)
		if err != nil || !bytes.Equal(b[:n], []byte{3, 4}) {
			t.Fatal("packet destination", n, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.readEndpoint(make([]byte, 8)); err == nil {
		t.Fatal("packet socket left open")
	}
}

type oracleBlockedDialer struct {
	oracleBindDialer
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (d *oracleBlockedDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	if d.calls.Add(1) == 1 {
		close(d.started)
	}
	<-d.release
	return d.socket, nil
}

func TestOracleParallelFirstWireGuardBind(t *testing.T) {
	peer := netip.MustParseAddrPort("192.0.2.1:51820")
	client, remote := net.Pipe()
	t.Cleanup(func() { client.Close(); remote.Close() })
	socket := &oracleReportedRemote{Conn: client, address: net.UDPAddrFromAddrPort(peer)}
	d := &oracleBlockedDialer{oracleBindDialer: oracleBindDialer{socket: socket}, started: make(chan struct{}), release: make(chan struct{})}
	b := NewClientBind(context.Background(), nil, d, true, peer, [3]uint8{})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	var done, launched sync.WaitGroup
	connect := func() {
		defer done.Done()
		if _, err := b.connect(); err != nil {
			t.Error(err)
		}
	}
	done.Add(1)
	go connect()
	<-d.started
	// Send and receive can request the same first connection concurrently.
	for i := 0; i < 4; i++ {
		done.Add(1)
		launched.Add(1)
		go func() { launched.Done(); connect() }()
	}
	launched.Wait()
	close(d.release)
	done.Wait()
	if got := d.calls.Load(); got != 1 {
		t.Fatalf("opened %d sockets for one bind", got)
	}
}
