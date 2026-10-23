// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	quic "github.com/sagernet/quic-go"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestQUICFragmentsInteroperableAndBounded(t *testing.T) {
	for _, size := range []int{1, 92, 148, 1000, 1001, 1380, 4096} {
		packet := bytes.Repeat([]byte{42}, size)
		parts, err := quicFragments(packet, 0x12345678)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parts[0][:4], []byte{0x12, 0x34, 0x56, 0x78}) {
			t.Fatal("network order")
		}
		assembly := make(quicAssembly)
		var recovered []byte
		for index := len(parts) - 1; index >= 0; index-- {
			recovered = assembly.receive(parts[index])
		}
		if !bytes.Equal(packet, recovered) || len(assembly) != 0 {
			t.Fatal("fragment round trip")
		}
	}
	assembly := make(quicAssembly)
	for id := uint32(0); id < 1000; id++ {
		parts, _ := quicFragments(make([]byte, 1380), id)
		assembly.receive(parts[0])
	}
	if len(assembly) != 64 {
		t.Fatal("unbounded pending fragments")
	}
	for _, data := range [][]byte{nil, make([]byte, 8), make([]byte, 1009), make([]byte, 1008)} {
		if assembly.receive(data) != nil {
			t.Fatal("malformed accepted")
		}
	}
}
func TestQUICRealTLSAuthenticationDatagramsAndDeadline(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vpn-admin.morandi.dpdns.org"}, DNSNames: []string{"vpn-admin.morandi.dpdns.org"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	transport := &quic.Transport{Conn: socket}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicALPN}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := make(chan error, 1)
	go func() {
		session, e := listener.Accept(ctx)
		if e != nil {
			server <- e
			return
		}
		defer session.CloseWithError(0, "")
		stream, e := session.AcceptStream(ctx)
		if e != nil {
			server <- e
			return
		}
		auth, e := io.ReadAll(io.LimitReader(stream, 45))
		if e != nil || string(auth) != string(bytes.Repeat([]byte{'a'}, 43))+"\n" {
			server <- io.ErrUnexpectedEOF
			return
		}
		stream.Write([]byte("OK\n"))
		stream.Close()
		assembly := make(quicAssembly)
		for {
			data, e := session.ReceiveDatagram(ctx)
			if e != nil {
				server <- e
				return
			}
			packet := assembly.receive(data)
			if packet == nil {
				continue
			}
			parts, _ := quicFragments(packet, 2)
			for _, part := range parts {
				if e = session.SendDatagram(part); e != nil {
					server <- e
					return
				}
			}
			<-ctx.Done()
			server <- nil
			return
		}
	}()
	physical, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	conn, err := dialLegacyQUIC(ctx, physical, socket.LocalAddr(), encoded, string(bytes.Repeat([]byte{'a'}, 43)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packet := append([]byte{4, 0, 0, 0}, bytes.Repeat([]byte{11}, 1376)...)
	if n, e := conn.Write(packet); e != nil || n != len(packet) {
		t.Fatal("datagram write", e)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	if n, e := conn.Read(buffer); e != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatal("datagram echo", e)
	}
	waiting := make(chan error, 1)
	conn.SetReadDeadline(time.Time{})
	go func() { _, e := conn.Read(buffer); waiting <- e }()
	time.Sleep(10 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	select {
	case e := <-waiting:
		if e == nil {
			t.Fatal("deadline ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("pending read deadline ignored")
	}
	conn.Close()
	cancel()
	<-server
}
