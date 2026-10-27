// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestNativeDeadlineChangeInterruptsPendingRead(t *testing.T) {
	c := newNativeConn(nil, nil)
	defer c.Close()
	result := make(chan error, 1)
	go func() { _, err := c.nextRead(); result <- err }()
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline update did not wake pending read")
	}
	if _, err := c.nextRead(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("expired deadline must persist", err)
	}
}

func TestNativeClearedDeadlineDoesNotFireOldTimer(t *testing.T) {
	c := newNativeConn(nil, nil)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	result := make(chan error, 1)
	go func() {
		p, err := c.nextRead()
		if err == nil && p.size != 17 {
			err = errors.New("wrong queued frame")
		}
		result <- err
	}()
	time.Sleep(5 * time.Millisecond)
	c.SetReadDeadline(time.Time{})
	time.Sleep(60 * time.Millisecond)
	select {
	case err := <-result:
		t.Fatal("cleared deadline completed read", err)
	default:
	}
	c.incoming <- nativeRead{size: 17}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued frame not delivered")
	}
}

func TestNativeCloseWakesReadWhileDeadlinesChange(t *testing.T) {
	c := newNativeConn(nil, nil)
	result := make(chan error, 1)
	go func() { _, err := c.nextRead(); result <- err }()
	for i := 0; i < 100; i++ {
		c.SetDeadline(time.Now().Add(time.Hour))
		c.SetReadDeadline(time.Time{})
	}
	c.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake pending read")
	}
}

func TestNativeClearingReadDeadlineRetainsWriteDeadline(t *testing.T) {
	c := newNativeConn(nil, nil)
	defer c.Close()
	c.SetDeadline(time.Now().Add(-time.Second))
	c.SetReadDeadline(time.Time{})
	packet := make([]byte, 32)
	packet[0] = 4
	if _, err := c.Write(packet); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline clear changed write deadline", err)
	}
}

func TestNativeExpiredSnapshotCannotOverrideClearedOrExtendedDeadline(t *testing.T) {
	c := newNativeConn(nil, nil)
	defer c.Close()
	for _, clear := range []bool{false, true} {
		c.SetReadDeadline(time.Now().Add(-time.Second))
		generation := c.readChanged
		if !c.readExpired(generation) {
			t.Fatal("current expired generation ignored")
		}
		if clear {
			c.SetReadDeadline(time.Time{})
		} else {
			c.SetReadDeadline(time.Now().Add(time.Hour))
		}
		if c.readExpired(generation) {
			t.Fatal("stale generation timed out a changed deadline")
		}
		if c.readExpired(c.readChanged) {
			t.Fatal("current live deadline considered expired")
		}
	}
}

// Pause the deadline setter while holding its mutex, with the old timer due.
// An expiry decision must wait for the new deadline generation, not complete
// the blocked read using a timer whose deadline was cleared or extended.
func TestNativePendingExpiryRechecksConcurrentDeadlineChange(t *testing.T) {
	for i := 0; i < 20; i++ {
		c := newNativeConn(nil, nil)
		c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		result := make(chan error, 1)
		go func() { _, err := c.nextRead(); result <- err }()
		time.Sleep(time.Millisecond)
		c.access.Lock()
		select {
		case err := <-result:
			c.access.Unlock()
			c.Close()
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
			continue // A genuinely expired read before the setter acquired its lock.
		default:
		}
		if i%2 == 0 {
			c.readAt = time.Time{}
		} else {
			c.readAt = time.Now().Add(time.Hour)
		}
		// Keep a setter's intermediate state private until after the old timer is
		// ready. The read either retries or blocks in expiry revalidation.
		time.Sleep(25 * time.Millisecond)
		close(c.readChanged)
		c.readChanged = make(chan struct{})
		c.access.Unlock()
		c.incoming <- nativeRead{size: 1}
		select {
		case err := <-result:
			if err != nil {
				t.Fatal("old timer overrode deadline change", err)
			}
		case <-time.After(time.Second):
			t.Fatal("changed deadline did not deliver frame")
		}
		c.Close()
	}
}
