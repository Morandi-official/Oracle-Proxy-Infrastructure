// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bufio"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestHolderResumesOnlyWithFreshConfigAndAudits(t *testing.T) {
	// Start an ordinary cold connection, then reuse the same empty adapter
	// twice. The peer callback owns tear-down before it can request a park.
	in := bufio.NewReader(strings.NewReader("first\nPARK\nRESUME\r\nsecond\nPARK\nRESUME\nthird\nPARK\n"))
	var events []string
	serve := func(resumed bool) (bool, error) {
		config, err := in.ReadString('\n')
		if err != nil {
			return false, err
		}
		if resumed != (config != "first\n") {
			t.Fatalf("unexpected resume state for %q", config)
		}
		events = append(events, strings.TrimSuffix(config, "\n"))
		command, err := readCoreCommand(in)
		if err != nil || command != "PARK" {
			t.Fatalf("peer command %q, %v", command, err)
		}
		events = append(events, "closed")
		return true, nil
	}
	park := func() error { events = append(events, "scrub"); return nil }
	verify := func() error { events = append(events, "audit"); return nil }
	ack := func() { events = append(events, "parked") }
	if err := serveAdapterLifetimes(in, false, serve, park, verify, ack); err != nil {
		t.Fatal(err)
	}
	want := []string{"first", "closed", "scrub", "parked", "audit", "second", "closed", "scrub", "parked", "audit", "third", "closed", "scrub", "parked"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events: %v", events)
	}
}

func TestEmptyHolderNeverStartsPeerOnEOFOrBadFrame(t *testing.T) {
	for _, frame := range []string{"", "PARK\n", "ACTIVATE\n", "RESUME", "RESUME RESUME RESUME\n", "{}\n"} {
		t.Run(frame, func(t *testing.T) {
			ack := false
			serve := func(bool) (bool, error) { t.Fatal("empty holder constructed a peer"); return false, nil }
			err := serveAdapterLifetimes(bufio.NewReader(strings.NewReader(frame)), true, serve, func() error { return nil }, func() error { t.Fatal("unexpected resume audit"); return nil }, func() { ack = true })
			if !ack || (err == nil) != (frame == "") {
				t.Fatalf("ack=%v err=%v", ack, err)
			}
		})
	}
}

func TestHolderRejectsUnverifiedParkOrResume(t *testing.T) {
	for _, stage := range []string{"close", "park", "resume"} {
		t.Run(stage, func(t *testing.T) {
			var acks int
			fail := errors.New("unsafe")
			serve := func(bool) (bool, error) {
				if stage == "close" {
					return true, fail
				}
				t.Fatal("started peer after failed native audit")
				return false, nil
			}
			park := func() error {
				if stage == "park" {
					return fail
				}
				return nil
			}
			verify := func() error { return fail }
			err := serveAdapterLifetimes(bufio.NewReader(strings.NewReader("RESUME\n{}\n")), stage != "close", serve, park, verify, func() { acks++ })
			if err == nil || (stage == "resume" && acks != 1) || (stage != "resume" && acks != 0) {
				t.Fatalf("acknowledgments=%d err=%v", acks, err)
			}
		})
	}
}

// Ensure EOF is a graceful close only at a command boundary.
func TestCoreCommandPartialEOF(t *testing.T) {
	for _, frame := range []string{"P", "ACTIVATE\r", "RESUME\x00"} {
		_, err := readCoreCommand(bufio.NewReader(strings.NewReader(frame)))
		if err == nil || err == io.EOF {
			t.Fatalf("partial command %q treated as complete", frame)
		}
	}
}

func TestHolderCreationRequiresPostJobAssignmentCommand(t *testing.T) {
	for _, frame := range []string{"", "HOLD", "RESUME\n", "{}\n", "HOLD alternate\n", "HOLD\n", "HOLD\r\n"} {
		want := frame == "HOLD\n" || frame == "HOLD\r\n"
		got := authorizeHolderStart(bufio.NewReader(strings.NewReader(frame))) == nil
		if want != got {
			t.Errorf("HOLD gate for %q: %v", frame, got)
		}
	}
}
