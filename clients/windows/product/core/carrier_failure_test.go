// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
)

func TestQUICFailureCategoriesDoNotExposeMessages(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("sensitive context: %w", context.DeadlineExceeded), "CARRIER_H3_TLS_TIMEOUT"},
		{&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "CARRIER_H3_TLS_CERTIFICATE"},
		{fmt.Errorf("sensitive socket failure"), "CARRIER_H3_TLS_FAILED"},
	}
	for _, c := range cases {
		if got := quicTLSFailure(c.err); got != c.want {
			t.Fatalf("category %s, expected %s", got, c.want)
		}
	}
}
