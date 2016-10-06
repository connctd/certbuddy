package certbuddy

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
	"path/filepath"
)

var (
	UnknownPemHeader       = errors.New("Unknown PEM header value")
	UnparseableCertificate = errors.New("Unparseable certificate")
)

func FileExists(name string) bool {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return false
	}
	return true
}

func CreateDirIfNotExists(dirPath string) error {
	if FileExists(dirPath) {
		// TODO check if path is actually a directory
		return nil
	}

	return os.MkdirAll(dirPath, 0700)
}

func ToPemBlock(data interface{}) ([]byte, error) {
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

func WritePEMBlock(data interface{}, keyPath string) error {
	pemBytes, err := ToPemBlock(data)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(keyPath, pemBytes, 0600)
}

func LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return PemBlockToPrivateKey(fileData)
}

func PemBlockToPrivateKey(pemBlockData []byte) (crypto.PrivateKey, error) {
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

func PemBlockToX509Certificate(pemBlockData []byte) ([]*x509.Certificate, error) {
	var pemBlock *pem.Block
	var remaining = pemBlockData
	certs := make([]*x509.Certificate, 0, 2)

	for {
		pemBlock, remaining = pem.Decode(remaining)
		if pemBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return certs, UnparseableCertificate
			}
			certs = append(certs, cert)
		}
		if len(remaining) == 0 {
			break
		}
	}
	return certs, nil
}

func LoadCertificateFromDisk(path string) ([]*x509.Certificate, error) {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return PemBlockToX509Certificate(fileData)
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

func EnsureParentPathExists(targetPath string) error {
	dirPath := filepath.Dir(targetPath)
	if !FileExists(dirPath) {
		return os.MkdirAll(dirPath, 0700)
	}
	return nil
}
