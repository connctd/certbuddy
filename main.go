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
	rsaKeyLength      = flag.Int("rsaLength", 4096, "Specify the length of RSA keys")
	consulAddr        = flag.String("consul", "", "Address of the consul agent to connect to (optional)")
	consulServiceName = flag.String("consulServiceName", "", "Name of the service to register with Consul")
	once              = flag.Bool("once", false, "Don't keep running in the background")

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

	client AutomatedCA
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

	fileStorage := &FileStorage{*keyPath, true}

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
		accountKey, err = rsa.GenerateKey(rand.Reader, *rsaKeyLength)
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

	ca := getClient(user)
	checker := TimeExpirationChecker{BestBefore: time.Hour * time.Duration(*renewBeforeFlag*24)}
	buddy, err := NewCertBuddy(fileStorage, fileStorage, ca, checker, issueDomains)
	if err != nil {
		log.Fatalf("Error creating buddy: %v", err)
	}
	go func() {
		for {
			if err := buddy.Loop(); err != nil {
				errc <- err
			}
			// TODO let the application sleep more intelligently
			log.Println("Waiting 12 hours, before checking again")
			time.Sleep(time.Hour * 12)
		}
	}()

	shutdown(<-errc)
}

func getClient(user *User) AutomatedCA {
	if client == nil {
		var err error
		client, err = NewAcmeClient(user, acme.RSA4096, *webrootPath)
		if err != nil {
			log.Fatalf("Can't create ACME client: %v", err)
		}
	}
	return client
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
