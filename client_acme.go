package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/xenolf/lego/acme"
)

const (
	letsencryptCaServer = "https://acme-v01.api.letsencrypt.org/directory"
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
	tlsCert, err := tls.X509KeyPair(certs.Certificate, certs.PrivateKey)
	// TODO verify that leaf exists
	failures = make(map[string]error)
	if err != nil {
		failures["_"] = err
	}
	return tlsCert.Leaf, failures
}

func (a *acmeClient) Renew(cert *x509.Certificate, privKey crypto.PrivateKey) (*x509.Certificate, error) {
	return nil, nil
}

func (a *acmeClient) Revoke(cert *x509.Certificate, privKey crypto.PrivateKey) error {
	return nil
}
