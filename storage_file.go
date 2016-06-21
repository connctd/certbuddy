package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
)

var (
	defaultCertExtension = "crt"
	defaultCertBaseName  = "server"

	defaultKeyName = "server.key"
)

type FileStorage struct {
	BasePath string
	Concat   bool
}

func (c *FileStorage) LoadCerts() ([]*x509.Certificate, error) {
	if c.Concat {
		certPath := path.Join(c.BasePath, fmt.Sprintf("%s.%s", defaultCertBaseName, defaultCertExtension))
		data, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		return pemBlockToX509Certificate(data)
	} else {
		certFiles, _ := filepath.Glob(path.Join(c.BasePath, fmt.Sprintf("%s*.%s", defaultCertBaseName, defaultCertExtension)))
		certs := make([]*x509.Certificate, 0, 2)
		for _, certFile := range certFiles {
			data, err := ioutil.ReadFile(path.Join(c.BasePath, certFile))
			if err != nil {
				return nil, err
			}
			cert, err := pemBlockToX509Certificate(data)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert...)
		}
		return certs, nil
	}
}

func (c *FileStorage) SaveCerts(certs []*x509.Certificate) error {
	if c.Concat {
		pemBytes := make([]byte, 0, 2048)
		for _, cert := range certs {
			data, err := toPemBlock(cert)
			if err != nil {
				return err
			}
			pemBytes = append(pemBytes, data...)
		}
		certPath := path.Join(c.BasePath, fmt.Sprintf("%s.%s", defaultCertBaseName, defaultCertExtension))
		return ioutil.WriteFile(certPath, pemBytes, 0600)
	} else {
		for i, cert := range certs {
			certFile := path.Join(c.BasePath, fmt.Sprintf("%s%d.%s", defaultCertBaseName, i, defaultCertExtension))
			pemBytes, err := toPemBlock(cert)
			if err != nil {
				return err
			}
			if err := ioutil.WriteFile(certFile, pemBytes, 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *FileStorage) LoadKey() (crypto.PrivateKey, error) {
	keyPath := path.Join(c.BasePath, defaultKeyName)
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return pemBlockToPrivateKey(data)
}

func (c *FileStorage) SaveKey(key crypto.PrivateKey) error {
	keyPath := path.Join(c.BasePath, defaultKeyName)
	pemBlockData, err := toPemBlock(key)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(keyPath, pemBlockData, 0600)
}

func (c *FileStorage) CertsExist() bool {
	certFiles, _ := filepath.Glob(path.Join(c.BasePath, fmt.Sprintf("%s*.%s", defaultCertBaseName, defaultCertExtension)))
	// TODO probably check if certificates are valid
	return len(certFiles) > 0
}

func (c *FileStorage) KeyExists() bool {
	return fileExists(path.Join(c.BasePath, defaultKeyName))
}
