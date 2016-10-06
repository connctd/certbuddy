package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/connctd/certbuddy"
	"github.com/connctd/certbuddy/acme"
	"github.com/connctd/certbuddy/consul"
	"github.com/connctd/certbuddy/file"
	"github.com/pkg/errors"
	"log"
	"path"
	"time"
)

type BuddyConfig struct {
	Email           string
	Domains         []string
	KeyPath         string
	CertPath        string
	ValidBefore     time.Duration
	WebrootPath     string
	AccountKeyPath  string
	ServiceName     string
	RegistryAddress string
}

type Buddy struct {
	registry        certbuddy.Registry
	ca              certbuddy.AutomatedCA
	config          *BuddyConfig
	checker         certbuddy.CertificateChecker
	user            *acme.User
	certStore       certbuddy.CertStorage
	privateKeyStore certbuddy.KeyStorage
	accountKeyStore certbuddy.KeyStorage
}

type dummyRegistry struct{}

func (d dummyRegistry) CertAvailable(cert *x509.Certificate) error {
	return nil
}

func (d dummyRegistry) CertsExpired(cert *x509.Certificate) error {
	return nil
}

var (
	rsaKeyLength = 4096
)

func NewBuddy(config BuddyConfig) (*Buddy, error) {
	if err := certbuddy.EnsureParentPathExists(config.AccountKeyPath); err != nil {
		return nil, errors.Wrap(err, "Can't create parent path for account key")
	}

	if err := certbuddy.EnsureParentPathExists(config.CertPath); err != nil {
		return nil, errors.Wrap(err, "Can't create parent path for certificate")
	}

	// Append an imaginary file name so filepath.Dir returns the correct path in
	// EnsureParentPathExists
	if err := certbuddy.EnsureParentPathExists(path.Join(config.WebrootPath, ".keep")); err != nil {
		return nil, errors.Wrap(err, "Can't create parent directory for webroot")
	}

	accountKeyStore := &file.FileStorage{BasePath: config.AccountKeyPath, Concat: false}
	var accountKey crypto.PrivateKey
	var err error
	if !accountKeyStore.KeyExists() {
		log.Printf("Account key %s does not exists, generating new key", config.AccountKeyPath)
		accountKey, err = rsa.GenerateKey(rand.Reader, rsaKeyLength)
		if err != nil {
			return nil, errors.Wrap(err, "Can't generate new RSA account key")
		}
		if err := accountKeyStore.SaveKey(accountKey); err != nil {
			return nil, errors.Wrap(err, "Can't write private account key")
		}
	} else {
		accountKey, err = accountKeyStore.LoadKey()
		if err != nil {
			return nil, errors.Wrap(err, "Unable to load private key for ACME account")
		}
	}

	// FIXME This should be consructed later
	user := &acme.User{
		Email:      config.Email,
		PrivateKey: accountKey,
	}

	checker := certbuddy.TimeExpirationChecker{BestBefore: config.ValidBefore}

	var registry certbuddy.Registry
	if config.RegistryAddress != "" {
		registry, err = consul.NewConsulRegistry(config.RegistryAddress, config.ServiceName)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to connect to Consul Registry")
		}
	} else {
		registry = dummyRegistry{}
	}

	return &Buddy{
		registry:        registry,
		config:          &config,
		checker:         checker,
		user:            user,
		accountKeyStore: accountKeyStore,
		certStore:       &file.FileStorage{BasePath: config.CertPath, Concat: true},
		privateKeyStore: &file.FileStorage{BasePath: config.KeyPath, Concat: false},
	}, nil

}

func (b *Buddy) EnsureCerts() error {
	log.Printf("Ensuring valid certificates for %+v", b.config.Domains)
	obtainCerts := false

	var privateKey crypto.PrivateKey
	if !b.privateKeyStore.KeyExists() {
		log.Println("Private key for ACME account doesn't exist, generating new key")
		obtainCerts = true
		privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyLength)
		if err != nil {
			return errors.Wrap(err, "Unable to generate missing private key")
		}
		if err := b.privateKeyStore.SaveKey(privateKey); err != nil {
			return errors.Wrap(err, "Unable to save private key")
		}
	} else {
		var err error
		privateKey, err = b.privateKeyStore.LoadKey()
		if err != nil {
			return errors.Wrap(err, "Unable to load private key")
		}
	}

	if !b.certStore.CertsExist() {
		obtainCerts = true
	}

	if obtainCerts {
		log.Println("Obtaining new certificate")
		if b.ca == nil {
			log.Println("Creating CA client")
			var err error
			b.ca, err = acme.NewAcmeClient(b.user, b.config.WebrootPath)
			if err != nil {
				return errors.Wrap(err, "Can't create ACME CA")
			}
		}
		result, errs := b.ca.ObtainCertificate(b.config.Domains, privateKey)
		if errs != nil {
			for domain, err := range errs {
				log.Printf("Error for domain %s: %+v", domain, err)
			}
			return errors.New("Error obtaining new certificate for private key")
		}
		if err := b.certStore.SaveCerts(result.AllCerts()); err != nil {
			return errors.Wrap(err, "Can't store obtained certificates")
		}
	} else {
		log.Println("Checking existing certificates")
		certs, err := b.certStore.LoadCerts()
		if err != nil {
			return errors.Wrap(err, "Unable to load certificates")
		}

		valid, err := b.checker.IsValid(certs[0])
		if err != nil {
			return errors.Wrap(err, "Unable to validate certificate")
		}
		if !valid {
			log.Println("Renewing existing certifcate")
			if b.ca == nil {
				var err error
				b.ca, err = acme.NewAcmeClient(b.user, b.config.WebrootPath)
				if err != nil {
					return errors.Wrap(err, "Can't create ACME CA")
				}
			}
			result, err := b.ca.Renew(certs[0], privateKey)
			if err != nil {
				errors.Wrap(err, "Unable to renew certificate")
			}
			if err := b.certStore.SaveCerts(result.AllCerts()); err != nil {
				return errors.Wrap(err, "Unable to save renewed Certificate")
			}
		}
	}
	log.Printf("Done for %+v", b.config.Domains)
	return nil
}
