package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"github.com/connctd/certbuddy"
	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/http/webroot"
	"io/ioutil"
	"log"
	"path"
)

const (
	stateBaseDir = "./.letsencrypt"
	defaultPerm  = 0600
)

var (
	NotImplemented = errors.New("Not implemented")
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

func NewAcmeClient(user *User, webrootPath string) (certbuddy.AutomatedCA, error) {
	client, err := acme.NewClient(letsencryptCaServer, user, acme.RSA4096)
	if err != nil {
		return nil, err
	}

	acmeClient := &acmeClient{
		client: client,
		user:   user,
	}
	stateDir, err := acmeClient.getStateDir()
	if err != nil {
		return nil, err
	}
	var regData acme.RegistrationResource
	regPath := path.Join(stateDir, "account.meta")
	if err := certbuddy.LoadJsonFromDisk(regPath, &regData); err != nil {
		log.Println("Registering new account")
		reg, err := client.Register()
		if err != nil {
			return nil, err
		}
		if err := certbuddy.StoreJsonToDisk(regPath, reg); err != nil {
			return nil, err
		}
		user.registration = reg
		if err := client.AgreeToTOS(); err != nil {
			return nil, err
		}
	} else {
		log.Println("Using existing account: %+v", regData)
		user.registration = &regData
	}
	provider, err := webroot.NewHTTPProvider(webrootPath)
	if err != nil {
		return nil, err
	}
	err = client.SetChallengeProvider(acme.HTTP01, provider)
	if err != nil {
		return nil, err
	}
	client.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})

	return acmeClient, nil
}

type acmeClient struct {
	client *acme.Client
	user   *User
}

func (a *acmeClient) ObtainCertificate(domains []string, privKey crypto.PrivateKey) (*certbuddy.CAResult, map[string]error) {
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
	x509Certs, err := certbuddy.PemBlockToX509Certificate(certs.Certificate)
	if err != nil {
		return nil, wrapErr(err)
	}
	result := &certbuddy.CAResult{}
	result.Certificate = x509Certs[0]
	if len(x509Certs) > 1 {
		result.IssuerChain = x509Certs[1:]
	}
	return result, nil
}

func wrapErr(err error) map[string]error {
	failures := make(map[string]error)
	failures["_"] = err
	return failures
}

func (a *acmeClient) Renew(cert *x509.Certificate, privKey crypto.PrivateKey) (*certbuddy.CAResult, error) {
	oldCertResource, err := a.toCertificateResource(cert, privKey)
	if err != nil {
		return nil, err
	}
	renewedCerts, err := a.client.RenewCertificate(oldCertResource, true)
	if err != nil {
		return nil, err
	}
	certs, err := certbuddy.PemBlockToX509Certificate(renewedCerts.Certificate)
	if err != nil {
		return nil, err
	}
	result := &certbuddy.CAResult{}
	result.Certificate = certs[0]
	if len(certs) > 1 {
		result.IssuerChain = certs[1:]
	}
	return result, nil
}

func (a *acmeClient) Revoke(cert *x509.Certificate, privKey crypto.PrivateKey) error {
	return NotImplemented
}

func (a *acmeClient) getStateDir() (string, error) {
	dir := path.Join(stateBaseDir, a.user.GetEmail())
	return dir, certbuddy.CreateDirIfNotExists(dir)
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
	certificatePem, err := certbuddy.ToPemBlock(cert)
	if err != nil {
		return certMeta, nil
	}
	privateKeyPem, err := certbuddy.ToPemBlock(privKey)
	if err != nil {
		return certMeta, nil
	}

	certMeta.Certificate = certificatePem
	certMeta.PrivateKey = privateKeyPem
	return certMeta, nil
}
