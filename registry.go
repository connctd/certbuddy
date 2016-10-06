package certbuddy

import (
	"crypto/x509"
)

type Registry interface {
	CertAvailable(cert *x509.Certificate) error
	CertsExpired(cert *x509.Certificate) error
}
