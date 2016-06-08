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
	"path"
	"strings"
	"syscall"
	"time"
)

var (
	email             = flag.String("email", "", "Specify the email address for the letsencrypt account")
	domains           = flag.String("domains", "", "Specify a comma seperated list of domains to get a certificate for")
	keyPath           = flag.String("keyPath", "", "Path to the private domain key")
	certPath          = flag.String("certPath", "", "Path to the domain certificte")
	renewBeforeFlag   = flag.Int("renewBefore", 30, "Renew before Duration before expiration in days")
	webrootPath       = flag.String("webroot", "", "Path to the webroot for the HTTP challenge")
	accountKeyPath    = flag.String("accountKey", "", "Path to the private key for the account")
	rasKeyLength      = flag.Int("rsaLength", 4096, "Specify the length of RSA keys")
	consulAddr        = flag.String("consul", "", "Address of the consul agent to connect to (optional)")
	consulServiceName = flag.String("consulServiceName", "", "Name of the service to register with Consul")

	flagNameMap = map[string]*string{
		"email":          email,
		"domains":        domains,
		"keyPath":        keyPath,
		"certPath":       certPath,
		"webrootPath":    webrootPath,
		"accountKeyPath": accountKeyPath,
	}
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

	if err := EnsureParentPathExists(*accountKeyPath); err != nil {
		log.Fatalf("Can't create parent path for account key: %v", err)
	}
	if err := EnsureParentPathExists(*keyPath); err != nil {
		log.Fatalf("Can't create parent path for private key: %v", err)
	}
	if err := EnsureParentPathExists(*certPath); err != nil {
		log.Fatalf("Can't create parent path for certificate: %v", err)
	}
	// Append an imaginary file name so filepath.Dir returns the correct path in
	// EnsureParentPathExists
	if err := EnsureParentPathExists(path.Join(*webrootPath, ".keep")); err != nil {
		log.Fatalf("Can't create parent directory for webroot: %v", err)
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

	if *consulAddr != "" {
		if err := ConnectConsul(*consulAddr); err != nil {
			log.Fatalf("Can't to connect to Consul Agent: %v", err)
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

	if err := RegisterCertsAvailable(*consulServiceName); err != nil {
		log.Fatalf("Can't register with Consul: %v", err)
	}

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
			if err := KeepCertsAvailableAlive(""); err != nil {
				log.Printf("Can't keep the service alive on Consul: %v", err)
				errc <- err
			}
			// TODO let the application sleep more intelligently
			log.Println("Waiting 12 hours, before checking again")
			time.Sleep(time.Hour * 12)
		}
	}()

	shutdown(<-errc)
}

func verifyFlags() error {
	for name, value := range flagNameMap {
		if *value == "" {
			return fmt.Errorf("The flag %s may not be empty", name)
		}
	}
	return nil
}

func shutdown(err error) {
	// On Exit deregister this service, so we don't have orphaned service registrations lingering around
	DeregisterCertsAvailable()
	log.Fatalf("Fatal: %v", err)
}

func interrupt() error {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	return fmt.Errorf("%s", <-c)
}
