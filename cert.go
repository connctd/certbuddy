package main

import (
	"crypto/x509"
	"time"
)

type CertificateChecker interface {
	IsValid(cert *x509.Certificate) (bool, error)
}

type TimeExpirationChecker struct {
	BestBefore time.Duration
}

func (t TimeExpirationChecker) IsValid(cert *x509.Certificate) (bool, error) {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false, nil
	}
	now = now.Add(t.BestBefore)
	if now.After(cert.NotAfter) {
		return false, nil
	}
	return true, nil
}
