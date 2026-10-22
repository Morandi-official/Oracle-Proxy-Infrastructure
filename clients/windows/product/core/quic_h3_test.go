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
	"github.com/sagernet/quic-go/http3"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRealHTTP3ConnectUDPContextAndAuthenticatedDatagrams(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "vpn-admin.morandi.dpdns.org"}, DNSNames: []string{"vpn-admin.morandi.dpdns.org"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	transport := &quic.Transport{Conn: socket}
	defer transport.Close()
	listener, e := transport.Listen(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token := string(bytes.Repeat([]byte{'a'}, 43))
	auth := make(chan bool, 1)
	server := &http3.Server{EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid := r.Method == "CONNECT" && r.Proto == "connect-udp" && r.URL.Path == "/.well-known/masque/udp/127.0.0.1/51820/" && r.Header.Get("Authorization") == "Bearer "+token
		auth <- valid
		if !valid {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		stream := w.(http3.HTTPStreamer).HTTPStream()
		defer stream.Close()
		go func() {
			for {
				b, e := stream.ReceiveDatagram(ctx)
				if e != nil {
					return
				}
				if len(b) < 1 || b[0] != 0 {
					return
				}
				if stream.SendDatagram(b) != nil {
					return
				}
			}
		}()
		for {
			packet, e := readCapsule(stream)
			if e != nil {
				return
			}
			if _, e = stream.Write(encodeCapsule(packet)); e != nil {
				return
			}
		}

	})}
	defer server.Close()
	go func() {
		session, e := listener.Accept(ctx)
		if e == nil {
			defer session.CloseWithError(0, "")
			server.ServeQUICConn(session)
		}
	}()
	physical, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	conn, e := dialQUIC(ctx, physical, socket.LocalAddr(), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), token)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if !<-auth {
		t.Fatal("missing HTTP3 CONNECT authentication")
	}
	packet := append([]byte{4, 0, 0, 0}, bytes.Repeat([]byte{55}, 1376)...)
	if _, e = conn.Write(packet); e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	n, e := conn.Read(buffer)
	if e != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatal("HTTP3 datagram echo", e)
	}
}
