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
	checker        CertificateChecker
	issueDomains   []string
}

func NewCertBuddy(certStore CertStorage, domainKeyStore KeyStorage, ca AutomatedCA,
	checker CertificateChecker, issueDomains []string) (*CertBuddy, error) {
	return &CertBuddy{
		certStore:      certStore,
		domainKeyStore: domainKeyStore,
		ca:             ca,
		checker:        checker,
		issueDomains:   issueDomains,
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
		domainKey, err = c.domainKeyStore.LoadKey()
	}
	if err != nil {
		return err
	}

	if !c.certStore.CertsExist() {
		needToObtainFirst = true
	}
	if needToObtainFirst {
		result, failures := c.ca.ObtainCertificate(c.issueDomains, domainKey)
		if len(failures) > 0 {
			printFailures(failures)
			return fmt.Errorf("Failed to obtain cerfificate")
		}
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
	if ok, err := c.checker.IsValid(certs[0]); !ok && err == nil {
		result, err := c.ca.Renew(certs[0], domainKey)
		if err != nil {
			return err
		}
		if err := c.certStore.SaveCerts(result.AllCerts()); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func printFailures(failures map[string]error) {
	for domain, err := range failures {
		log.Printf("%s: %v", domain, err)
	}
}
