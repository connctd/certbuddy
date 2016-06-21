package main

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"path/filepath"
	"testing"
)

var (
	testBasePath = "./stortest"
)

func TestStorCertFilesConcated(t *testing.T) {
	os.MkdirAll(testBasePath, 0700)
	assert := assert.New(t)
	stor := FileStorage{testBasePath, true}
	assert.False(stor.CertsExist())
	certs := make([]*x509.Certificate, 0, 3)
	for i := 0; i < 3; i++ {
		certs = append(certs, &x509.Certificate{})
	}
	err := stor.SaveCerts(certs)
	assert.Nil(err)
	assert.True(stor.CertsExist())
	certFiles, _ := filepath.Glob(path.Join(testBasePath, "*"))
	assert.Len(certFiles, 1)
	os.RemoveAll(testBasePath)
}

func TestStoreCertFilesNonConcated(t *testing.T) {
	os.MkdirAll(testBasePath, 0700)
	assert := assert.New(t)
	stor := FileStorage{testBasePath, false}
	assert.False(stor.CertsExist())
	certs := make([]*x509.Certificate, 0, 3)
	for i := 0; i < 3; i++ {
		certs = append(certs, &x509.Certificate{})
	}
	err := stor.SaveCerts(certs)
	assert.Nil(err)
	assert.True(stor.CertsExist())
	certFiles, _ := filepath.Glob(path.Join(testBasePath, "*"))
	assert.Len(certFiles, 3)
	os.RemoveAll(testBasePath)
}
