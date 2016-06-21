package main

import (
	"crypto"
	"crypto/x509"
)

type CertStorage interface {
	LoadCerts() ([]*x509.Certificate, error)
	SaveCerts(certs []*x509.Certificate) error
	CertsExist() bool
}

type KeyStorage interface {
	LoadKey() (crypto.PrivateKey, error)
	SaveKey(key crypto.PrivateKey) error
	KeyExists() bool
}

type MultiOutputCertStorage struct {
	stor     CertStorage
	outStors []CertStorage
}

func NewMultiOutputCertStorage(mainStore CertStorage, outputStores ...CertStorage) CertStorage {
	return &MultiOutputCertStorage{
		stor:     mainStore,
		outStors: outputStores,
	}
}

func (m *MultiOutputCertStorage) LoadCerts() ([]*x509.Certificate, error) {
	return m.stor.LoadCerts()
}

func (m *MultiOutputCertStorage) SaveCerts(certs []*x509.Certificate) error {
	if err := m.stor.SaveCerts(certs); err != nil {
		return err
	}
	for _, stor := range m.outStors {
		if err := stor.SaveCerts(certs); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiOutputCertStorage) CertsExist() bool {
	return m.stor.CertsExist()
}
