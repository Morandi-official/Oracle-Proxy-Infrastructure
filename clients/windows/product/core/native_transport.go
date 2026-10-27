// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type nativeRead struct {
	data  *[4096]byte
	size  int
	index int
	err   error
}
type nativeConn struct {
	relayConn
	sockets     []net.Conn
	ports       []uint16
	incoming    chan nativeRead
	free        chan *[4096]byte
	done        chan struct{}
	readChanged chan struct{}
	mu          sync.Mutex
	winner      int
	attempt     int
	sentIndex   int
	lastInit    []byte
	once        sync.Once
	eventMu     sync.Mutex
	events      map[string]int
}

// Fixed, bounded diagnostic events only: no addresses, packet bytes or keys.
func (c *nativeConn) event(index int, event string) {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	if c.events == nil {
		c.events = make(map[string]int)
	}
	key := fmt.Sprintf("NATIVE_UDP_%d_%s", c.ports[index], event)
	if c.events[key] < 32 {
		c.events[key]++
		fmt.Fprintln(os.Stderr, key)
	}
}
func nativeError(err error) uint32 {
	var code syscall.Errno
	if errors.As(err, &code) {
		return uint32(code)
	}
	return 0
}

func newNativeConn(sockets []net.Conn, ports []uint16) *nativeConn {
	c := &nativeConn{sockets: sockets, ports: ports, incoming: make(chan nativeRead, 16), free: make(chan *[4096]byte, 16+len(sockets)), done: make(chan struct{}), readChanged: make(chan struct{}), winner: -1, attempt: -1, sentIndex: -1}
	// One frame per queued delivery plus one per socket reader. Ownership
	// moves reader -> incoming -> Read -> free; never reuse a queued frame.
	for i := 0; i < cap(c.free); i++ {
		c.free <- new([4096]byte)
	}
	for i, s := range sockets {
		buffers, bufferErr := tuneNativeSocket(s)
		for _, item := range []struct {
			name  string
			value int
		}{{"RCVBUF_BEFORE", buffers.receiveBefore}, {"SNDBUF_BEFORE", buffers.sendBefore}, {"RCVBUF_AFTER", buffers.receiveAfter}, {"SNDBUF_AFTER", buffers.sendAfter}} {
			fmt.Fprintf(os.Stderr, "NATIVE_UDP_%d_%s_%d\n", ports[i], item.name, item.value)
		}
		if bufferErr != nil {
			fmt.Fprintf(os.Stderr, "NATIVE_UDP_%d_SOCKET_BUFFER_ERROR_%d\n", ports[i], nativeError(bufferErr))
		}
		go func(i int, s net.Conn) {
			for {
				var b *[4096]byte
				select {
				case b = <-c.free:
				case <-c.done:
					return
				}
				n, e := s.Read(b[:])
				if e != nil {
					select {
					case <-c.done:
						c.recycle(b)
						return
					default:
					}
					c.mu.Lock()
					retired := c.winner >= 0 && c.winner != i
					c.mu.Unlock()
					if retired {
						c.recycle(b)
						return
					}
					c.event(i, fmt.Sprintf("READ_ERROR_%d", nativeError(e)))
				}
				if e == nil && !validPacket(b[:n]) {
					c.event(i, "RECV_INVALID")
					c.recycle(b)
					continue
				}
				if e == nil && b[0] == 2 {
					c.event(i, "RECV_REPLY")
				}
				if e == nil && b[0] == 3 {
					c.event(i, "RECV_COOKIE")
				}
				select {
				case c.incoming <- nativeRead{b, n, i, e}:
				case <-c.done:
					c.recycle(b)
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
func (c *nativeConn) recycle(b *[4096]byte) {
	select {
	case c.free <- b:
	case <-c.done:
	}
}

// Native UDP reads do not need a per-packet cancellation context. Wake a
// blocked read only when its absolute deadline changes or the socket closes;
// the normal no-deadline packet path allocates no timer or context.
func (c *nativeConn) nextRead() (nativeRead, error) {
	for {
		c.access.Lock()
		at, changed := c.readAt, c.readChanged
		c.access.Unlock()
		var timer *time.Timer
		var expiry <-chan time.Time
		if !at.IsZero() {
			left := time.Until(at)
			if left <= 0 {
				if c.readExpired(changed) {
					return nativeRead{}, os.ErrDeadlineExceeded
				}
				continue
			}
			timer = time.NewTimer(left)
			expiry = timer.C
		}
		var packet nativeRead
		var err error
		retry := false
		select {
		case packet = <-c.incoming:
		case <-changed:
			retry = true
		case <-expiry:
			if c.readExpired(changed) {
				err = os.ErrDeadlineExceeded
			} else {
				retry = true
			}
		case <-c.done:
			err = net.ErrClosed
		}
		if timer != nil {
			timer.Stop()
		}
		if retry {
			continue
		}
		return packet, err
	}
}

// A changed deadline and its old timer can become ready together. Never let
// select's random choice turn a cancelled/extended deadline into a timeout.
func (c *nativeConn) readExpired(generation <-chan struct{}) bool {
	c.access.Lock()
	defer c.access.Unlock()
	return generation == c.readChanged && !c.readAt.IsZero() && !time.Now().Before(c.readAt)
}
func (c *nativeConn) SetReadDeadline(at time.Time) error {
	c.access.Lock()
	if !at.Equal(c.readAt) {
		c.readAt = at
		close(c.readChanged)
		c.readChanged = make(chan struct{})
	}
	c.access.Unlock()
	return nil
}
func (c *nativeConn) SetDeadline(at time.Time) error {
	c.access.Lock()
	c.writeAt = at
	if !at.Equal(c.readAt) {
		c.readAt = at
		close(c.readChanged)
		c.readChanged = make(chan struct{})
	}
	c.access.Unlock()
	return nil
}
func (c *nativeConn) Read(b []byte) (int, error) {
	failed := map[int]bool{}
	for {
		p, err := c.nextRead()
		if err != nil {
			return 0, err
		}
		c.mu.Lock()
		winner := c.winner
		if p.err != nil {
			c.recycle(p.data)
			c.mu.Unlock()
			failed[p.index] = true
			if winner == p.index || len(failed) == len(c.sockets) {
				return 0, p.err
			}
			continue
		}
		if winner >= 0 && winner != p.index {
			c.recycle(p.data)
			c.mu.Unlock()
			continue
		}
		// A reply to the previous initiation can arrive after WG has
		// generated a fresh one on the other port. It must not pin the
		// socket to an obsolete handshake and discard the current reply.
		// A reconnected socket can resume an existing WG crypto session
		// with data before another initiation. Accept the socket actually
		// written, not only sockets selected by a new handshake. WG still
		// authenticates all returned bytes; unsolicited sockets stay rejected.
		if winner < 0 && (c.sentIndex < 0 || p.index != c.sentIndex) {
			c.event(p.index, "RECV_OBSOLETE")
			c.recycle(p.data)
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
		if len(b) < p.size {
			c.recycle(p.data)
			return 0, io.ErrShortBuffer
		}
		n := copy(b, p.data[:p.size])
		c.recycle(p.data)
		return n, nil
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
	// A WireGuard peer rejects an initiation whose encrypted timestamp it has
	// already accepted, even if the first reply was lost. Never race copies of
	// one initiation to two aliases of that peer. Try the next port only with
	// a NEW initiation generated by WireGuard's own retry timer. The winning
	// port is remembered by the service for subsequent connections.
	if c.winner < 0 && b[0] == 1 && !bytes.Equal(b, c.lastInit) {
		c.attempt++
		c.lastInit = append(c.lastInit[:0], b...)
		fmt.Fprintf(os.Stderr, "CARRIER_NATIVE_TRY_%d\n", c.ports[c.attempt%len(c.sockets)])
	}
	i := c.attempt
	if i < 0 {
		i = 0
	}
	write := func(index int) (int, error) {
		c.sentIndex = index
		n, err := c.sockets[index].Write(b)
		if err != nil {
			c.event(index, fmt.Sprintf("WRITE_ERROR_%d", nativeError(err)))
		}
		if n == len(b) && b[0] == 1 {
			c.event(index, "SEND_INIT")
		}
		return n, err
	}
	if c.winner >= 0 {
		return write(c.winner)
	}
	n, err := write(i % len(c.sockets))
	if err != nil && n == 0 && b[0] == 1 && len(c.sockets) > 1 {
		// A synchronous failure sent none of THIS initiation. Try the
		// other socket now: returning the first error would make ClientBind
		// close both sockets and restart forever on the same blocked port.
		c.attempt = i + 1
		fmt.Fprintf(os.Stderr, "CARRIER_NATIVE_TRY_%d\n", c.ports[c.attempt%len(c.sockets)])
		return write(c.attempt % len(c.sockets))
	}
	return n, err
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
