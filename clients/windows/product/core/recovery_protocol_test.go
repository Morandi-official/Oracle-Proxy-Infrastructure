package main

import (
	"strings"
	"testing"
)

func TestAdapterRecoveryFrameBoundary(t *testing.T) {
	valid := "{\"guid\":\"" + recoveryGUID + "\",\"luid\":123456789}\n"
	got, err := readAdapterRecoveryRequest(strings.NewReader(valid))
	if err != nil || got.GUID != recoveryGUID || got.LUID != 123456789 {
		t.Fatal("valid fixed frame refused")
	}
	if _, err := readAdapterRecoveryRequest(strings.NewReader(strings.Replace(valid, "\n", "\r\n", 1))); err != nil {
		t.Fatal("Windows single-line terminator refused")
	}
	for _, invalid := range []string{
		strings.TrimSuffix(valid, "\n"), valid + "\n", valid + "{}\n",
		strings.Replace(valid, "123456789", "0", 1), strings.Replace(valid, "123456789", "-1", 1),
		strings.Replace(valid, "123456789", "1e3", 1), strings.Replace(valid, "123456789", "1.0", 1),
		strings.Replace(valid, "123456789", "18446744073709551616", 1),
		strings.Replace(valid, "123456789", "\"123456789\"", 1),
		strings.Replace(valid, "123456789}", "123456789,\"luid\":4}", 1),
		strings.Replace(valid, "123456789}", "123456789,\"path\":\"C:\\\\Windows\"}", 1),
		strings.Replace(valid, recoveryGUID, "00000000-0000-0000-0000-000000000000", 1),
		strings.Replace(valid, "123456789}", "123456789,\"guid\":\""+recoveryGUID+"\"}", 1),
		"[]\n", "null\n", strings.Repeat(" ", 1024) + valid,
	} {
		if _, err := readAdapterRecoveryRequest(strings.NewReader(invalid)); err == nil {
			t.Fatalf("unsafe frame accepted: %q", invalid)
		}
	}
}
