package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/xenolf/lego/acme"
	"io/ioutil"
	"path"
)

const (
	letsencryptCaServer = "https://acme-v01.api.letsencrypt.org/directory"
	stateBaseDir        = "./.letsencrypt"
	defaultPerm         = 0600
	NotImplemented      = errors.New("Not implemented")
)

type User struct {
	Email        string
	PrivateKey   crypto.PrivateKey
	registration *acme.RegistrationResource
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *acme.RegistrationResource {
	return u.registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}

func NewAcmeClient(user *User, keyType acme.KeyType) (AutomatedCA, error) {
	client, err := acme.NewClient(letsencryptCaServer, user, keyType)
	if err != nil {
		return nil, err
	}
	reg, err := client.Register()
	if err != nil {
		return nil, err
	}
	user.registration = reg
	if err := client.AgreeToTOS(); err != nil {
		return nil, err
	}
	return &acmeClient{
		client: client,
		user:   user,
	}, nil
}

type acmeClient struct {
	client *acme.Client
	user   *User
}

func (a *acmeClient) ObtainCertificate(domains []string, privKey crypto.PrivateKey) (*x509.Certificate, map[string]error) {
	certs, failures := a.client.ObtainCertificate(domains, true, privKey)
	if len(failures) > 0 {
		return nil, failures
	}
	stateDir, err := a.getStateDir()
	if err != nil {
		return nil, wrapErr(err)
	}
	certMetaPath := path.Join(stateDir, "certs.meta")
	certMetaData, err := json.Marshal(certs)
	if err != nil {
		return nil, wrapErr(err)
	}
	err = ioutil.WriteFile(certMetaPath, certMetaData, defaultPerm)
	if err != nil {
		return nil, wrapErr(err)
	}
	x509Cert, err := pemBlockToX509Certificate(certs.Certificate)
	if err != nil {
		return nil, wrapErr(err)
	}
	return x509Cert, nil
}

func wrapErr(err error) map[string]error {
	failures := make(map[string]error)
	failures["_"] = err
	return failures
}

func (a *acmeClient) Renew(cert *x509.Certificate, privKey crypto.PrivateKey) (*x509.Certificate, error) {
	oldCertResource, err := a.toCertificateResource(cert, privKey)
	if err != nil {
		return nil, errr
	}
	renewedCerts, err := a.client.RenewCertificate(cert, bundle)
	if err != nil {
		return nil, err
	}
	return pemBlockToX509Certificate(renewedCerts.Certificate)
}

func (a *acmeClient) Revoke(cert *x509.Certificate, privKey crypto.PrivateKey) error {
	return NotImplemented
}

func (a *acmeClient) getStateDir() (string, error) {
	dir := path.Join(stateBaseDir, a.user.GetEmail())
	return dir, CreateDirIfNotExists(dir)
}

func (a *acmeClient) toCertificateResource(cert *x509.Certificate, privKey crypto.PrivateKey) (acme.CertificateResource, error) {
	var certMeta acme.CertificateResource
	stateDir, err := a.getStateDir()
	if err != nil {
		return certMeta, err
	}
	certMetaPath := path.Join(stateDir, "certs.meta")
	certMetaData, err := ioutil.ReadFile(certMetaPath)
	if err != nil {
		return certMeta, err
	}

	err = json.Unmarshal(certMetaData, &certMeta)
	certificatePem, err := toPemBlock(cert)
	if err != nil {
		return certMeta, nil
	}
	privateKeyPem, err := toPemBlock(privKey)
	if err != nil {
		return certMeta, nil
	}

	certMeta.Certificate = certificatePem
	certMeta.PrivateKey = privateKeyPem
	return certMeta, nil
}
