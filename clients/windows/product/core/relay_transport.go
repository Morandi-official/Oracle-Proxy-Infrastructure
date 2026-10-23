// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"github.com/coder/websocket"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const relayURL = "wss://vpn-admin.morandi.dpdns.org/api/client/relay"
const relayProtocol = "oracle-wireguard-v1"

func dialRelay(ctx context.Context, client *http.Client, url, token string) (net.Conn, error) {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(deadline, url, &websocket.DialOptions{
		HTTPClient: client, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
		Subprotocols: []string{relayProtocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, errors.New("RELAY_HTTPS_CONNECT_FAILED")
	}
	if conn.Subprotocol() != relayProtocol {
		conn.CloseNow()
		return nil, errors.New("RELAY_PROTOCOL_REJECTED")
	}
	conn.SetReadLimit(4096)
	return &relayConn{conn: conn}, nil
}

type relayConn struct {
	conn            *websocket.Conn
	access          sync.Mutex
	readAt, writeAt time.Time
	readOp, writeOp *relayOperation
}
type relayOperation struct {
	cancel context.CancelFunc
	timer  *time.Timer
}

func (o *relayOperation) arm(at time.Time) {
	if o.timer != nil {
		o.timer.Stop()
		o.timer = nil
	}
	if !at.IsZero() {
		o.timer = time.AfterFunc(time.Until(at), o.cancel)
	}
}

func validPacket(b []byte) bool {
	if len(b) < 4 || len(b) > 4096 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}
	switch b[0] {
	case 1:
		return len(b) == 148
	case 2:
		return len(b) == 92
	case 3:
		return len(b) == 64
	case 4:
		return len(b) >= 32
	}
	return false
}
func (c *relayConn) operation(read bool) (context.Context, context.CancelFunc) {
	c.access.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	op := &relayOperation{cancel: cancel}
	at := c.writeAt
	if read {
		at = c.readAt
		c.readOp = op
	} else {
		c.writeOp = op
	}
	op.arm(at)
	c.access.Unlock()
	return ctx, func() {
		c.access.Lock()
		defer c.access.Unlock()
		if op.timer != nil {
			op.timer.Stop()
		}
		op.cancel()
		if read && c.readOp == op {
			c.readOp = nil
		}
		if !read && c.writeOp == op {
			c.writeOp = nil
		}
	}
}
func (c *relayConn) Read(b []byte) (int, error) {
	ctx, cancel := c.operation(true)
	defer cancel()
	kind, packet, err := c.conn.Read(ctx)
	if err != nil {
		c.access.Lock()
		expired := !c.readAt.IsZero() && !time.Now().Before(c.readAt)
		c.access.Unlock()
		if expired {
			return 0, os.ErrDeadlineExceeded
		}
		return 0, net.ErrClosed
	}
	if kind != websocket.MessageBinary || !validPacket(packet) {
		c.conn.CloseNow()
		return 0, errors.New("RELAY_FRAME_REJECTED")
	}
	if len(b) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, packet), nil
}
func (c *relayConn) Write(b []byte) (int, error) {
	if !validPacket(b) {
		return 0, errors.New("RELAY_FRAME_REJECTED")
	}
	ctx, cancel := c.operation(false)
	defer cancel()
	if err := c.conn.Write(ctx, websocket.MessageBinary, b); err != nil {
		c.access.Lock()
		expired := !c.writeAt.IsZero() && !time.Now().Before(c.writeAt)
		c.access.Unlock()
		if expired {
			return 0, os.ErrDeadlineExceeded
		}
		return 0, net.ErrClosed
	}
	return len(b), nil
}
func (c *relayConn) Close() error        { return c.conn.CloseNow() }
func (c *relayConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *relayConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(152, 67, 156, 100), Port: 51820}
}
func (c *relayConn) SetDeadline(at time.Time) error {
	c.access.Lock()
	c.readAt = at
	c.writeAt = at
	if c.readOp != nil {
		c.readOp.arm(at)
	}
	if c.writeOp != nil {
		c.writeOp.arm(at)
	}
	c.access.Unlock()
	return nil
}
func (c *relayConn) SetReadDeadline(at time.Time) error {
	c.access.Lock()
	c.readAt = at
	if c.readOp != nil {
		c.readOp.arm(at)
	}
	c.access.Unlock()
	return nil
}
func (c *relayConn) SetWriteDeadline(at time.Time) error {
	c.access.Lock()
	c.writeAt = at
	if c.writeOp != nil {
		c.writeOp.arm(at)
	}
	c.access.Unlock()
	return nil
}
