// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type nativeRead struct {
	data  []byte
	index int
	err   error
}
type nativeConn struct {
	relayConn
	sockets  []net.Conn
	ports    []uint16
	incoming chan nativeRead
	done     chan struct{}
	mu       sync.Mutex
	winner   int
	once     sync.Once
}

func newNativeConn(sockets []net.Conn, ports []uint16) *nativeConn {
	c := &nativeConn{sockets: sockets, ports: ports, incoming: make(chan nativeRead, 16), done: make(chan struct{}), winner: -1}
	for i, s := range sockets {
		go func(i int, s net.Conn) {
			for {
				b := make([]byte, 4096)
				n, e := s.Read(b)
				if e == nil && !validPacket(b[:n]) {
					continue
				}
				select {
				case c.incoming <- nativeRead{b[:n], i, e}:
				case <-c.done:
					return
				}
				if e != nil {
					return
				}
			}
		}(i, s)
	}
	return c
}
func (c *nativeConn) Read(b []byte) (int, error) {
	ctx, cancel := c.operation(true)
	defer cancel()
	failed := map[int]bool{}
	for {
		select {
		case <-ctx.Done():
			return 0, os.ErrDeadlineExceeded
		case <-c.done:
			return 0, net.ErrClosed
		case p := <-c.incoming:
			c.mu.Lock()
			winner := c.winner
			if p.err != nil {
				c.mu.Unlock()
				failed[p.index] = true
				if winner == p.index || len(failed) == len(c.sockets) {
					return 0, p.err
				}
				continue
			}
			if winner >= 0 && winner != p.index {
				c.mu.Unlock()
				continue
			}
			if winner < 0 {
				c.winner = p.index
				fmt.Fprintln(os.Stderr, fmt.Sprintf("CARRIER_NATIVE_%d", c.ports[p.index]))
				for i, s := range c.sockets {
					if i != p.index {
						s.Close()
					}
				}
			}
			c.mu.Unlock()
			if len(b) < len(p.data) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, p.data), nil
		}
	}
}
func (c *nativeConn) Write(b []byte) (int, error) {
	if !validPacket(b) {
		return 0, errors.New("NATIVE_FRAME_REJECTED")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.access.Lock()
	expired := !c.writeAt.IsZero() && !time.Now().Before(c.writeAt)
	c.access.Unlock()
	if expired {
		return 0, os.ErrDeadlineExceeded
	}
	if c.winner >= 0 {
		return c.sockets[c.winner].Write(b)
	}
	var success bool
	for i, s := range c.sockets {
		if i == 0 {
			_, e := s.Write(b)
			success = e == nil
		} else {
			packet := append([]byte(nil), b...)
			go func(i int, s net.Conn) {
				timer := time.NewTimer(150 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-c.done:
					return
				}
				c.mu.Lock()
				defer c.mu.Unlock()
				if c.winner < 0 {
					s.Write(packet)
				}
			}(i, s)
		}
	}
	// A primary send error can coexist with a healthy scheduled secondary.
	if success || len(c.sockets) > 1 {
		return len(b), nil
	}
	return 0, errors.New("NATIVE_SEND_FAILED")
}
func (c *nativeConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		for _, s := range c.sockets {
			s.Close()
		}
	})
	return nil
}
func (c *nativeConn) LocalAddr() net.Addr { return c.sockets[0].LocalAddr() }
func (c *nativeConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.winner
	if i < 0 {
		i = 0
	}
	return c.sockets[i].RemoteAddr()
}
