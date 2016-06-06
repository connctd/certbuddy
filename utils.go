package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

var (
	UnknownPemHeader = errors.New("Unknown PEM header value")
)

func fileExists(name string) bool {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return false
	}
	return true
}

func CreateDirIfNotExists(dirPath string) error {
	if fileExists(dirPath) {
		// TODO check if path is actually a directory
		return nil
	}

	return os.MkdirAll(dirPath, 0600)
}

func toPemBlock(data interface{}) ([]byte, error) {
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
	return pemBytes, nil
}

func writePEMBlock(data interface{}, keyPath string) error {
	pemBytes, err := toPemBlock(data)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(keyPath, pemBytes, 0600)
}

func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pemBlockToPrivateKey(fileData)
}

func pemBlockToPrivateKey(pemBlockData []byte) (crypto.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBlockData)
	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(pemBlock.Bytes)
	default:
		return nil, UnknownPemHeader
	}
}

func pemBlockToX509Certificate(pemBlockData []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBlockData)
	if pemBlock.Type != "CERTIFICATE" {
		return nil, UnknownPemHeader
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}

func loadCertificateFromDisk(path string) (*x509.Certificate, error) {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pemBlockToX509Certificate(fileData)
}

func LoadJsonFromDisk(jsonPath string, data interface{}) error {
	dataBytes, err := ioutil.ReadFile(jsonPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(dataBytes, data)
}

func StoreJsonToDisk(jsonPath string, data interface{}) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(jsonPath, jsonBytes, 0600)
}
