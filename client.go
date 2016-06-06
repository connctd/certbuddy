package main

import (
	"crypto"
	"crypto/x509"
)

type AutomatedCA interface {
	ObtainCertificate(domains []string, privKey crypto.PrivateKey) (*x509.Certificate, map[string]error)
	Renew(cert *x509.Certificate, privKey crypto.PrivateKey) (*x509.Certificate, error)
	Revoke(cert *x509.Certificate, privKey crypto.PrivateKey) error
}
