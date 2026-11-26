// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

func readCoreCommand(input *bufio.Reader) (string, error) {
	frame, err := input.ReadSlice('\n')
	if len(frame) == 0 && err == io.EOF {
		return "", io.EOF
	}
	if err != nil || len(frame) > 16 {
		return "", errors.New("frame")
	}
	return strings.TrimSuffix(string(frame[:len(frame)-1]), "\r"), nil
}

func authorizeHolderStart(input *bufio.Reader) error {
	command, err := readCoreCommand(input)
	if err != nil || command != "HOLD" {
		return errors.New("frame")
	}
	return nil
}

// serve must return only after closing its scopes, transport and proofs. While
// parked no configuration is held; RESUME begins a new, separately framed
// configuration, using this process's original, freshly audited adapter.
func serveAdapterLifetimes(input *bufio.Reader, parked bool, serve func(resumed bool) (park bool, err error), parkAdapter, verifyAdapter func() error, acknowledge func()) error {
	resumed := false
	for {
		if parked {
			if err := parkAdapter(); err != nil {
				return errors.New("close")
			}
			acknowledge()
			command, err := readCoreCommand(input)
			if err == io.EOF {
				return nil
			}
			if err != nil || command != "RESUME" {
				return errors.New("frame")
			}
			if err := verifyAdapter(); err != nil {
				return errors.New("create")
			}
			resumed = true
		}
		var err error
		parked, err = serve(resumed)
		if err != nil || !parked {
			return err
		}
	}
}
