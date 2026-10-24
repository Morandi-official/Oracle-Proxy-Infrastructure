// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// Distinct encrypted-packet-shaped frames without network timing noise.
// Payload checks expose premature reuse while the receive queue is full.
type generatedNativeConn struct {
	net.Conn
	done     chan struct{}
	once     sync.Once
	sequence uint64
}

func (s *generatedNativeConn) Read(b []byte) (int, error) {
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	s.sequence++
	b[0] = 4
	b[1] = 0
	b[2] = 0
	b[3] = 0
	binary.LittleEndian.PutUint64(b[4:12], s.sequence)
	for i := 12; i < 1232; i++ {
		b[i] = byte(s.sequence)
	}
	return 1232, nil
}
func (s *generatedNativeConn) Write(b []byte) (int, error) { return len(b), nil }
func (s *generatedNativeConn) Close() error                { s.once.Do(func() { close(s.done) }); return nil }
func generatedNative() *nativeConn {
	c := newNativeConn([]net.Conn{&generatedNativeConn{done: make(chan struct{})}}, []uint16{8443})
	c.Write(append([]byte{4, 0, 0, 0}, make([]byte, 28)...))
	return c
}
func TestNativeReceiveQueuedFramesRemainDistinct(t *testing.T) {
	c := generatedNative()
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	time.Sleep(10 * time.Millisecond)
	var b [4096]byte
	for sequence := uint64(1); sequence <= 10000; sequence++ {
		n, err := c.Read(b[:])
		if err != nil || n != 1232 {
			t.Fatal(n, err)
		}
		if binary.LittleEndian.Uint64(b[4:12]) != sequence {
			t.Fatal("queued packet overwritten", sequence)
		}
		for _, v := range b[12:n] {
			if v != byte(sequence) {
				t.Fatal("payload overwritten", sequence)
			}
		}
	}
}
func TestNativeReceiveShortBufferAndClose(t *testing.T) {
	c := generatedNative()
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Fatal("short buffer accepted")
	}
	var b [4096]byte
	if n, err := c.Read(b[:]); n != 1232 || err != nil {
		t.Fatal("short read damaged next frame", n, err)
	}
	c.Close()
	c.Close()
}
func BenchmarkNativeReceive(b *testing.B) {
	c := generatedNative()
	defer c.Close()
	var packet [4096]byte
	b.SetBytes(1232)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := c.Read(packet[:]); n != 1232 || err != nil {
			b.Fatal(n, err)
		}
	}
}
