package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
)

type CertBuddy struct {
	certStore      CertStorage
	domainKeyStore KeyStorage
	ca             AutomatedCA
	notifier       Notifier
	checker        CertificateChecker
	issueDomains   []string
}

func NewCertBuddy(certStore CertStorage, domainKeyStore KeyStorage, ca AutomatedCA, notifier Notifier,
	checker CertificateChecker, issueDomains []string) (*CertBuddy, error) {
	return &CertBuddy{
		certStore:      certStore,
		domainKeyStore: domainKeyStore,
		ca:             ca,
		checker:        checker,
		issueDomains:   issueDomains,
		notifier:       notifier,
	}, nil
}

func (c *CertBuddy) Loop() error {

	var err error
	var domainKey crypto.PrivateKey
	needToObtainFirst := false

	if !c.domainKeyStore.KeyExists() {
		log.Printf("Generating new private domain key")
		needToObtainFirst = true
		domainKey, err = rsa.GenerateKey(rand.Reader, *rsaKeyLength)
		if err != nil {
			return err
		}
		if err := c.domainKeyStore.SaveKey(domainKey); err != nil {
			return err
		}
	} else {
		log.Printf("Loading domain key")
		domainKey, err = c.domainKeyStore.LoadKey()
	}
	if err != nil {
		return err
	}

	if !c.certStore.CertsExist() {
		needToObtainFirst = true
	}
	if needToObtainFirst {
		log.Printf("Obtaining new certificate")
		result, failures := c.ca.ObtainCertificate(c.issueDomains, domainKey)
		if len(failures) > 0 {
			printFailures(failures)
			return fmt.Errorf("Failed to obtain cerfificate")
		}
		log.Printf("Saving obtained certificate")
		err = c.certStore.SaveCerts(result.AllCerts())
		if err != nil {
			return err
		}
	}

	certs, err := c.certStore.LoadCerts()
	if err != nil {
		return err
	}
	if certs == nil || len(certs) == 0 {
		return fmt.Errorf("No certificates loaded from certificate store")
	}
	log.Printf("Checkig if certificate is still valid")
	if ok, err := c.checker.IsValid(certs[0]); !ok && err == nil {
		if notifier != nil {
			if err := notifier.NotifyCertsUnavailable(); err != nil {
				log.Printf("Can't notify that certs are unavailable: %v", err)
			}
		}
		log.Printf("Certificate needs to be renewed")
		result, err := c.ca.Renew(certs[0], domainKey)
		if err != nil {
			log.Printf("Failed to renew certificate")
			return err
		}
		log.Printf("Certificate has been renewed")
		if err := c.certStore.SaveCerts(result.AllCerts()); err != nil {
			log.Printf("Failed to store certificate")
			return err
		}
		if notifier != nil {
			if err := notifier.NotifyCertsAvailable(); err != nil {
				log.Printf("Can't notify that certs are available after renewal")
			}
			if err := notifier.NotifyCertsRenewed(); err != nil {
				log.Printf("Can't notify that certs are renewed")
			}
		}
	} else if err != nil {
		log.Printf("Failed to check certificate")
		return err
	} else if c.notifier != nil {
		if err := c.notifier.NotifyCertsAvailable(); err != nil {
			log.Printf("Can't notify that certs are available")
			return err
		}
	}
	return nil
}

func printFailures(failures map[string]error) {
	for domain, err := range failures {
		log.Printf("%s: %v", domain, err)
	}
}
