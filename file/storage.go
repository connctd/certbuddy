package file

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/connctd/certbuddy"
	"github.com/pkg/errors"
	"io/ioutil"
	"path"
	"path/filepath"
)

var (
	defaultCertExtension = "crt"
	defaultCertBaseName  = "server"

	defaultKeyName = "private.key"
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
			return nil, errors.Wrap(err, "Unable to read concatenated certificate file")
		}
		if len(data) == 0 {
			return nil, errors.New("Empty file")
		}
		return certbuddy.PemBlockToX509Certificate(data)
	} else {
		certFiles, _ := filepath.Glob(path.Join(c.BasePath, fmt.Sprintf("%s*.%s", defaultCertBaseName, defaultCertExtension)))
		certs := make([]*x509.Certificate, 0, 2)
		for _, certFile := range certFiles {
			data, err := ioutil.ReadFile(path.Join(c.BasePath, certFile))
			if err != nil {
				return nil, err
			}
			cert, err := certbuddy.PemBlockToX509Certificate(data)
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
			data, err := certbuddy.ToPemBlock(cert)
			if err != nil {
				return err
			}
			pemBytes = append(pemBytes, data...)
		}
		certPath := path.Join(c.BasePath, fmt.Sprintf("%s.%s", defaultCertBaseName, defaultCertExtension))
		if err := certbuddy.EnsureParentPathExists(certPath); err != nil {
			return errors.Wrap(err, "Unable to create parent path for certificate file")
		}
		if err := ioutil.WriteFile(certPath, pemBytes, 0600); err != nil {
			return errors.Wrap(err, "Unable to write concatenated certificate file")
		}
	} else {
		for i, cert := range certs {
			certFile := path.Join(c.BasePath, fmt.Sprintf("%s%d.%s", defaultCertBaseName, i, defaultCertExtension))
			if err := certbuddy.EnsureParentPathExists(certFile); err != nil {
				return errors.Wrap(err, "Unable to create parent path for certificate")
			}
			pemBytes, err := certbuddy.ToPemBlock(cert)
			if err != nil {
				return errors.Wrap(err, "Unable to convert certificate to PEM block")
			}
			if err := ioutil.WriteFile(certFile, pemBytes, 0600); err != nil {
				return errors.Wrap(err, "Unable to write certificate file")
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
	return certbuddy.PemBlockToPrivateKey(data)
}

func (c *FileStorage) SaveKey(key crypto.PrivateKey) error {
	keyPath := path.Join(c.BasePath, defaultKeyName)
	pemBlockData, err := certbuddy.ToPemBlock(key)
	if err != nil {
		return err
	}
	if err := certbuddy.EnsureParentPathExists(keyPath); err != nil {
		return errors.Wrap(err, "Unable to create parent path to store key file")
	}
	if err := ioutil.WriteFile(keyPath, pemBlockData, 0600); err != nil {
		return errors.Wrap(err, "Unable to write private key file")
	}
	return nil
}

func (c *FileStorage) CertsExist() bool {
	certFiles, _ := filepath.Glob(path.Join(c.BasePath, fmt.Sprintf("%s*.%s", defaultCertBaseName, defaultCertExtension)))
	// TODO probably check if certificates are valid
	// TODO check fir empty file
	return len(certFiles) > 0
}

func (c *FileStorage) KeyExists() bool {
	return certbuddy.FileExists(path.Join(c.BasePath, defaultKeyName))
}
