package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

var (
	UnknownPemHeader = errors.New("Unknown PEM header value")
)

func fileExists(name string) bool {
	if _, err := os.Stat(name); err != os.ErrNotExist {
		return true
	}
	return false
}

func writePEMBlock(data interface{}, keyPath string) error {
	var pemBlock *pem.Block
	switch key := data.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		break
	case *x509.Certificate:
		pemBlock = &pem.Block{Type: "CERTIFICATE", Bytes: key.Raw}
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return ioutil.WriteFile(keyPath, pemBytes, 0600)
}

func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(fileData)
	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(pemBlock.Bytes)
	default:
		return nil, UnknownPemHeader
	}
}

func loadCertificateFromDisk(path string) (*x509.Certificate, error) {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(fileData)
	if pemBlock.Type != "CERTIFICATE" {
		return nil, UnknownPemHeader
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}
