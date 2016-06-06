package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/xenolf/lego/acme"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	email           = flag.String("email", "", "Specify the email address for the letsencrypt account")
	domains         = flag.String("domains", "", "Specify a comma seperated list of domains to get a certificate for")
	keyPath         = flag.String("keyPath", "", "Path to the private domain key")
	certPath        = flag.String("certPath", "", "Path to the domain certificte")
	renewBeforeFlag = flag.Int("renewBefore", 30, "Renew before Duration before expiration in days")
	webrootPath     = flag.String("webroot", "", "Path to the webroot for the HTTP challenge")
	accountKeyPath  = flag.String("accountKey", "", "Path to the private key for the account")
	rasKeyLength    = flag.Int("rsaLength", 4096, "Specify the length of RSA keys")
)

var (
	issueDomains []string
)

func main() {
	flag.Parse()
	if err := verifyFlags(); err != nil {
		log.Fatalf("Specified invalid or too few flags: %v", err)
	}

	errc := make(chan error)

	go func() {
		errc <- interrupt()
	}()

	if strings.Contains(*domains, ",") {
		issueDomains = strings.Split(*domains, ",")
	} else {
		issueDomains = make([]string, 1, 1)
		issueDomains[0] = *domains
	}

	var accountKey crypto.PrivateKey
	var err error
	if fileExists(*accountKeyPath) {
		log.Printf("Loading private key for account from %s", *accountKeyPath)
		accountKey, err = loadPrivateKey(*accountKeyPath)
		if err != nil {
			log.Fatalf("Can't load private account key: %v", err)
		}
	} else {
		log.Printf("Account key %s does not exists, generating new key", *accountKeyPath)
		accountKey, err = rsa.GenerateKey(rand.Reader, *rasKeyLength)
		if err != nil {
			log.Fatalf("Can't generate new RSA account key: %v", err)
		}
		if err := writePEMBlock(accountKey, *accountKeyPath); err != nil {
			log.Fatalf("Can't write private account key to %s: %v", *accountKeyPath, err)
		}
	}

	user := &User{
		Email:      *email,
		PrivateKey: accountKey,
	}

	client, err := NewAcmeClient(user, acme.RSA4096, *webrootPath)
	if err != nil {
		log.Fatalf("Can't create ACME client: %v", err)
	}

	needToObtainFirst := false

	if !fileExists(*certPath) || !fileExists(*keyPath) {
		log.Printf("We currently don't have a full set of certificate and private key, obtaining this first")
		needToObtainFirst = true
	}

	var domainPrivateKey crypto.PrivateKey
	if fileExists(*keyPath) {
		log.Printf("Loading private key for domains from %s", *keyPath)
		domainPrivateKey, err = loadPrivateKey(*keyPath)
		if err != nil {
			log.Fatalf("Can't load private key from %s: %v", *keyPath, err)
		}
	} else {
		log.Printf("Private key %s not found. Generating new one", *keyPath)
		domainPrivateKey, err = rsa.GenerateKey(rand.Reader, *rasKeyLength)
		if err != nil {
			log.Fatalf("Can't generate private key: %v", err)
		}
		if err := writePEMBlock(domainPrivateKey, *keyPath); err != nil {
			log.Fatalf("Can't write private key to %s: %v", *keyPath, err)
		}
	}

	if needToObtainFirst {
		log.Printf("Obtaining new certificate")
		cert, err := client.ObtainCertificate(issueDomains, domainPrivateKey)
		if err != nil {
			log.Fatalf("Failed to obtain signed certificate from CA: %v", err)
		}
		if err := writePEMBlock(cert, *certPath); err != nil {
			log.Fatalf("Can't write certificate to %s: %v", *certPath, err)
		}
	}
	checker := TimeExpirationChecker{BestBefore: time.Hour * time.Duration(*renewBeforeFlag*24)}

	go func() {
		for {
			log.Printf("Checking if the certificate is valid for at least %d more days", *renewBeforeFlag)
			clientCert, err := loadCertificateFromDisk(*certPath)
			if err != nil {
				log.Printf("Can't read certificate from %s: %v", *certPath, err)
				errc <- err
			}
			if ok, err := checker.IsValid(clientCert); !ok {
				log.Println("Certificate is not valid long enough, renewing")
				domainPrivateKey, err := loadPrivateKey(*keyPath)
				if err != nil {
					log.Printf("Can't load private key from %s: %v", *keyPath, err)
					errc <- err
				}
				renewedCert, err := client.Renew(clientCert, domainPrivateKey)
				if err := writePEMBlock(renewedCert, *certPath); err != nil {
					log.Printf("Can't write renewed certificate to %s: %v", *certPath, err)
					errc <- err
				}
				log.Println("Renewed the certificate")
			} else if err != nil {
				log.Printf("Error checking the certificate: %v", err)
				errc <- err
			} else {
				log.Printf("Certificate is still valid")
			}
			// TODO let the application sleep more intelligently
			log.Println("Waiting 12 hours, before checking again")
			time.Sleep(time.Hour * 12)
		}
	}()

	log.Fatalf("Fatal: %v", <-errc)
}

func verifyFlags() error {
	return nil
}

func interrupt() error {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	return fmt.Errorf("%s", <-c)
}
