package certbuddy

import (
	"crypto"
	"crypto/x509"
)

type CAResult struct {
	Certificate *x509.Certificate
	IssuerChain []*x509.Certificate
}

func (c *CAResult) AllCerts() []*x509.Certificate {
	allCerts := make([]*x509.Certificate, 0, len(c.IssuerChain)+1)
	allCerts = append(allCerts, c.Certificate)
	allCerts = append(allCerts, c.IssuerChain...)
	return allCerts
}

type AutomatedCA interface {
	ObtainCertificate(domains []string, privKey crypto.PrivateKey) (*CAResult, map[string]error)
	Renew(cert *x509.Certificate, privKey crypto.PrivateKey) (*CAResult, error)
	Revoke(cert *x509.Certificate, privKey crypto.PrivateKey) error
}
