package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

const recoveryGUID = "62e2af98-7089-6f2c-246b-4a5960cfc978"

type adapterRecoveryRequest struct {
	GUID string
	LUID uint64
}

// Only a single, bounded frame on the SYSTEM parent's private stdin is accepted.
// Parse fields explicitly: encoding/json struct decoding alone permits duplicates.
func readAdapterRecoveryRequest(input io.Reader) (adapterRecoveryRequest, error) {
	var value adapterRecoveryRequest
	fail := errors.New("adapter recovery frame")
	data, err := io.ReadAll(io.LimitReader(input, 1025))
	if err != nil || len(data) == 0 || len(data) > 1024 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return value, fail
	}
	decoder := json.NewDecoder(bytes.NewReader(data[:len(data)-1]))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return value, fail
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || (name != "guid" && name != "luid") {
			return value, fail
		}
		seen[name] = true
		switch name {
		case "guid":
			if decoder.Decode(&value.GUID) != nil {
				return value, fail
			}
		case "luid":
			var raw json.RawMessage
			if decoder.Decode(&raw) != nil {
				return value, fail
			}
			if len(raw) == 0 {
				return value, fail
			}
			for _, digit := range raw {
				if digit < '0' || digit > '9' {
					return value, fail
				}
			}
			value.LUID, err = strconv.ParseUint(string(raw), 10, 64)
			if err != nil {
				return value, fail
			}
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 2 || value.GUID != recoveryGUID || value.LUID == 0 {
		return value, fail
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return value, fail
	}
	return value, nil
}
