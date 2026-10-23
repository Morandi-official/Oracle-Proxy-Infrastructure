// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"fmt"
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/url"

	"os"
	"time"
)

func carrierStage(stage string) { fmt.Fprintln(os.Stderr, stage) }
func dialQUIC(ctx context.Context, physical net.PacketConn, destination net.Addr, certificate, token string) (net.Conn, error) {
	cfg, err := quicTLS(certificate)
	if err != nil {
		physical.Close()
		return nil, err
	}
	cfg.NextProtos = []string{"h3"}
	transport := &quic.Transport{Conn: physical}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	carrierStage("CARRIER_H3_TLS")
	session, err := transport.Dial(deadline, destination, cfg, &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: 8})
	fail := func() (net.Conn, error) {
		if session != nil {
			session.CloseWithError(0x100, "RELAY_CLOSED")
		}
		transport.Close()
		physical.Close()
		return nil, errors.New("HTTP3_CONNECT_FAILED")
	}
	if err != nil {
		carrierStage(quicTLSFailure(err))
		return fail()
	}
	carrierStage("CARRIER_H3_SETTINGS")
	client := (&http3.Transport{EnableDatagrams: true, DisableCompression: true, MaxResponseHeaderBytes: 4096}).NewClientConn(session)
	select {
	case <-client.ReceivedSettings():
	case <-deadline.Done():
		return fail()
	}
	if !client.Settings().EnableExtendedConnect || !client.Settings().EnableDatagrams {
		return fail()
	}
	stream, err := client.OpenRequestStream(deadline)
	if err != nil {
		return fail()
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	request := &http.Request{Method: http.MethodConnect, Proto: "connect-udp", URL: &url.URL{Scheme: "https", Host: "vpn-admin.morandi.dpdns.org", Path: "/.well-known/masque/udp/127.0.0.1/51820/"}, Host: "vpn-admin.morandi.dpdns.org", Header: http.Header{"Authorization": []string{"Bearer " + token}, "Capsule-Protocol": []string{"?1"}}}
	carrierStage("CARRIER_H3_AUTH")
	if err = stream.SendRequestHeader(request); err != nil {
		return fail()
	}
	response, err := stream.ReadResponse()
	if err != nil || response.StatusCode != 200 {
		return fail()
	}
	stream.SetDeadline(time.Time{})
	carrierStage("CARRIER_H3_READY")
	c := &quicConn{session: session, transport: transport, physical: physical, h3stream: stream, h3Packets: make(chan []byte, 32), parts: make(quicAssembly)}
	c.startHTTP3Readers()
	return c, nil
}

func encodeCapsule(packet []byte) []byte {
	n := len(packet) + 1
	data := []byte{0, byte((n >> 8) | 0x40), byte(n), 0}
	return append(data, packet...)
}
func capsuleVarint(reader io.Reader) (uint64, error) {
	var first [1]byte
	if _, e := io.ReadFull(reader, first[:]); e != nil {
		return 0, e
	}
	size := 1 << uint(first[0]>>6)
	value := uint64(first[0] & 63)
	var rest [7]byte
	if _, e := io.ReadFull(reader, rest[:size-1]); e != nil {
		return 0, e
	}
	for _, b := range rest[:size-1] {
		value = (value << 8) | uint64(b)
	}
	return value, nil
}
func readCapsule(reader io.Reader) ([]byte, error) {
	kind, e := capsuleVarint(reader)
	if e != nil {
		return nil, e
	}
	n, e := capsuleVarint(reader)
	if e != nil {
		return nil, e
	}
	if kind != 0 || n < 1 || n > 4097 {
		return nil, errors.New("HTTP3_CAPSULE_REJECTED")
	}
	data := make([]byte, int(n))
	if _, e = io.ReadFull(reader, data); e != nil {
		return nil, e
	}
	if data[0] != 0 {
		return nil, errors.New("HTTP3_CONTEXT_REJECTED")
	}
	return data[1:], nil
}
func (c *quicConn) startHTTP3Readers() {
	deliver := func(packet []byte) bool {
		if !validPacket(packet) {
			c.Close()
			return false
		}
		select {
		case c.h3Packets <- packet:
			return true
		case <-c.session.Context().Done():
			return false
		}
	}
	go func() {
		for {
			data, e := c.h3stream.ReceiveDatagram(c.session.Context())
			if e != nil {
				c.Close()
				return
			}
			if len(data) < 1 || data[0] != 0 {
				c.Close()
				return
			}
			if !deliver(data[1:]) {
				return
			}
		}
	}()
	go func() {
		for {
			data, e := readCapsule(c.h3stream)
			if e != nil {
				c.Close()
				return
			}
			if !deliver(data) {
				return
			}
		}
	}()
}
