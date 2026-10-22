// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	quic "github.com/sagernet/quic-go"
)

const quicALPN = "oracle-wireguard-quic-v1"
const quicChunk = 1000

type quicPiece struct {
	at     time.Time
	total  int
	pieces [][]byte
}
type quicAssembly map[uint32]*quicPiece

func (a quicAssembly) receive(data []byte) []byte {
	now := time.Now()
	for id, item := range a {
		if now.Sub(item.at) >= 2*time.Second {
			delete(a, id)
		}
	}
	if len(data) < 9 || len(data) > 1008 {
		return nil
	}
	id, total, index, count := binary.BigEndian.Uint32(data), int(binary.BigEndian.Uint16(data[4:])), int(data[6]), int(data[7])
	if total < 1 || total > 4096 || count != (total+quicChunk-1)/quicChunk || index >= count {
		return nil
	}
	want := min(quicChunk, total-index*quicChunk)
	if len(data)-8 != want {
		return nil
	}
	item := a[id]
	if item == nil {
		if len(a) >= 64 {
			return nil
		}
		item = &quicPiece{at: now, total: total, pieces: make([][]byte, count)}
		a[id] = item
	}
	if item.total != total {
		delete(a, id)
		return nil
	}
	item.pieces[index] = append([]byte(nil), data[8:]...)
	for _, piece := range item.pieces {
		if piece == nil {
			return nil
		}
	}
	packet := make([]byte, 0, total)
	for _, piece := range item.pieces {
		packet = append(packet, piece...)
	}
	delete(a, id)
	return packet
}
func quicFragments(data []byte, id uint32) ([][]byte, error) {
	if len(data) < 1 || len(data) > 4096 {
		return nil, errors.New("QUIC_FRAME_REJECTED")
	}
	count := (len(data) + quicChunk - 1) / quicChunk
	parts := make([][]byte, count)
	for index := range parts {
		piece := make([]byte, 8+min(quicChunk, len(data)-index*quicChunk))
		binary.BigEndian.PutUint32(piece, id)
		binary.BigEndian.PutUint16(piece[4:], uint16(len(data)))
		piece[6] = byte(index)
		piece[7] = byte(count)
		copy(piece[8:], data[index*quicChunk:])
		parts[index] = piece
	}
	return parts, nil
}
func quicTLS(certificate string) (*tls.Config, error) {
	if len(certificate) > 4096 {
		return nil, errors.New("QUIC_CERTIFICATE_REJECTED")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certificate)) {
		return nil, errors.New("QUIC_CERTIFICATE_REJECTED")
	}
	return &tls.Config{RootCAs: roots, ServerName: "vpn-admin.morandi.dpdns.org", MinVersion: tls.VersionTLS13, NextProtos: []string{quicALPN}}, nil
}
func dialQUIC(ctx context.Context, physical net.PacketConn, destination net.Addr, certificate, token string) (net.Conn, error) {
	cfg, err := quicTLS(certificate)
	if err != nil {
		physical.Close()
		return nil, err
	}
	transport := &quic.Transport{Conn: physical}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	session, err := transport.Dial(deadline, destination, cfg, &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: -1})
	fail := func() (net.Conn, error) {
		if session != nil {
			session.CloseWithError(0x100, "RELAY_CLOSED")
		}
		transport.Close()
		physical.Close()
		return nil, errors.New("QUIC_CONNECT_FAILED")
	}
	if err != nil {
		return fail()
	}
	stream, err := session.OpenStreamSync(deadline)
	if err != nil {
		return fail()
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(stream, token+"\n"); err != nil {
		return fail()
	}
	if err = stream.Close(); err != nil {
		return fail()
	}
	ack := make([]byte, 4)
	n, err := io.ReadFull(stream, ack)
	if n != 3 || err != io.ErrUnexpectedEOF || string(ack[:3]) != "OK\n" {
		return fail()
	}
	return &quicConn{session: session, transport: transport, physical: physical, parts: make(quicAssembly)}, nil
}

type quicConn struct {
	relayConn // shared deadline handling; Read/Write/Close are overridden below
	session   *quic.Conn
	transport *quic.Transport
	physical  net.PacketConn
	parts     quicAssembly
	writeLock sync.Mutex
	number    uint32
	once      sync.Once
}

func (c *quicConn) Read(b []byte) (int, error) {
	ctx, cancel := c.operation(true)
	defer cancel()
	for {
		data, err := c.session.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return 0, os.ErrDeadlineExceeded
			}
			return 0, net.ErrClosed
		}
		packet := c.parts.receive(data)
		if packet == nil {
			continue
		}
		if !validPacket(packet) {
			c.Close()
			return 0, errors.New("QUIC_FRAME_REJECTED")
		}
		if len(b) < len(packet) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, packet), nil
	}
}
func (c *quicConn) Write(b []byte) (int, error) {
	if !validPacket(b) {
		return 0, errors.New("QUIC_FRAME_REJECTED")
	}
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	c.access.Lock()
	expired := !c.writeAt.IsZero() && !time.Now().Before(c.writeAt)
	c.access.Unlock()
	if expired {
		return 0, os.ErrDeadlineExceeded
	}
	c.number++
	parts, _ := quicFragments(b, c.number)
	for _, part := range parts {
		if err := c.session.SendDatagram(part); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}
func (c *quicConn) Close() error {
	c.once.Do(func() { c.session.CloseWithError(0x100, "RELAY_CLOSED"); c.transport.Close(); c.physical.Close() })
	return nil
}
