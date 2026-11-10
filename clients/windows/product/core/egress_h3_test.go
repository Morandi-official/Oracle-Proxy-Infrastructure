package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"github.com/sagernet/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTraceAddressRejectsMissingDuplicatePrivateAndOversized(t *testing.T) {
	for _, body := range []string{"", "ip=127.0.0.1\n", "ip=10.0.0.6\n", "ip=wrong\n", "ip=152.67.154.225\nip=152.67.154.225\n", strings.Repeat("a", 8193)} {
		if _, err := traceAddress([]byte(body)); err == nil {
			t.Fatal("invalid trace accepted")
		}
	}
	for _, ip := range []string{"152.67.154.225", "2603:c020:c015:8100::10"} {
		if got, err := traceAddress([]byte("h=trace\nip=" + ip + "\n")); err != nil || got != ip {
			t.Fatal("valid trace rejected")
		}
	}
}
func TestProbePacketCannotChangeRemote(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	p := fixedProbePacket{Conn: a, remote: &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}}
	if _, err := p.WriteTo([]byte("secret"), &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 443}); err == nil {
		t.Fatal("migration accepted")
	}
	if _, err := p.WriteTo([]byte("secret"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 444}); err == nil {
		t.Fatal("port changed")
	}
}
func TestRealHTTP3TraceValidatesCertificateHostnameAndCancellation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(84), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	server := http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h3"}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/cdn-cgi/trace" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte("ip=152.67.154.225\n"))
	})}
	defer server.Close()
	go server.Serve(socket)
	destination := M.ParseSocksaddr(socket.LocalAddr().String())
	for _, test := range []struct {
		name  string
		root  *x509.CertPool
		host  string
		valid bool
	}{{"trusted", roots, "127.0.0.1", true}, {"untrusted", x509.NewCertPool(), "127.0.0.1", false}, {"wrong hostname", roots, "1.1.1.1", false}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := net.Dial("udp", destination.String())
			if err != nil {
				t.Fatal(err)
			}
			ip, err := probeHTTP3Connection(ctx, conn, destination, &tls.Config{RootCAs: test.root, ServerName: test.host, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}})
			if test.valid && (err != nil || ip != "152.67.154.225") {
				t.Fatalf("valid proof failed: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("TLS failure accepted")
			}
		})
	}
	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conn, err := net.Dial("udp", silent.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = probeHTTP3Connection(ctx, conn, M.ParseSocksaddr(silent.LocalAddr().String()), &tls.Config{ServerName: "127.0.0.1", NextProtos: []string{"h3"}})
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("cancellation not bounded")
	}
}
