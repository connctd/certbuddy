package main

import (
	"crypto"
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

type memStore struct {
	certificates []*x509.Certificate
	key          crypto.PrivateKey
}

func (m *memStore) LoadCerts() ([]*x509.Certificate, error) {
	return m.certificates, nil
}

func (m *memStore) SaveCerts(certs []*x509.Certificate) error {
	m.certificates = certs
	return nil
}

func (m *memStore) CertsExist() bool {
	return m.certificates != nil && len(m.certificates) > 0
}

func (m *memStore) LoadKey() (crypto.PrivateKey, error) {
	return m.key, nil
}

func (m *memStore) SaveKey(key crypto.PrivateKey) error {
	m.key = key
	return nil
}

func (m *memStore) KeyExists() bool {
	return m.key != nil
}

type mockCa struct{}

func (m *mockCa) ObtainCertificate(domains []string, privKey crypto.PrivateKey) (*CAResult, map[string]error) {
	cert := &x509.Certificate{}
	result := &CAResult{
		Certificate: cert,
	}
	return result, nil
}

func (m *mockCa) Renew(cert *x509.Certificate, privKey crypto.PrivateKey) (*CAResult, error) {
	result := &CAResult{
		Certificate: cert,
	}
	return result, nil
}

func (m *mockCa) Revoke(cert *x509.Certificate, privKey crypto.PrivateKey) error {
	return nil
}

type mockChecker struct {
	result bool
}

func (m mockChecker) IsValid(cert *x509.Certificate) (bool, error) {
	return m.result, nil
}

func TestBuddyNoKeysAndCertificates(t *testing.T) {
	assert := assert.New(t)

	store := &memStore{}
	ca := &mockCa{}
	checker := mockChecker{}
	issueDomains := []string{"test.example.com"}

	buddy, err := NewCertBuddy(store, store, ca, nil, checker, issueDomains)
	assert.Nil(err)
	assert.NotNil(buddy)

	err = buddy.Loop()
	assert.Nil(err)
	assert.Len(store.certificates, 1)
	assert.NotNil(store.key)
}
