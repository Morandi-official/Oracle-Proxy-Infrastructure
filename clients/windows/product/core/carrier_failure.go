// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

func quicTLSFailure(err error) string {
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "CARRIER_H3_TLS_TIMEOUT"
	}
	var verification *tls.CertificateVerificationError
	var invalid x509.CertificateInvalidError
	var authority x509.UnknownAuthorityError
	if errors.As(err, &verification) || errors.As(err, &invalid) || errors.As(err, &authority) {
		return "CARRIER_H3_TLS_CERTIFICATE"
	}
	return "CARRIER_H3_TLS_FAILED"
}
