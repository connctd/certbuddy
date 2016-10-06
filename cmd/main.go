package main

import (
	"flag"
	"fmt"
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
	consulAddr      = flag.String("consul", "", "Address of the consul agent to connect to (optional)")
	once            = flag.Bool("once", false, "Don't keep running in the background")
	serviceName     = flag.String("serviceName", "tls-certs", "Specify a service name for your service registry")
	config          = flag.String("config", "", "Specify a config file for multiple accounts (unused at the moment)")

	flagNameMap = map[string]*string{
		"email":          email,
		"domains":        domains,
		"certPath":       certPath,
		"webrootPath":    webrootPath,
		"accountKeyPath": accountKeyPath,
	}
)

func main() {
	flag.Parse()
	if err := verifyFlags(); err != nil {
		log.Fatalf("Specified invalid or too few flags: %+v", err)
	}

	errc := make(chan error)

	go func() {
		errc <- interrupt()
	}()

	go func() {
		var configs []BuddyConfig
		if *config == "" {
			config, err := buddyConfigFromFlags()
			if err != nil {
				log.Fatalf("Can't create valid config from flags and no config file is specified: %+v", err)
			}
			configs = []BuddyConfig{config}
		}

		buddies := make([]*Buddy, 0, 10)
		for _, config := range configs {
			buddy, err := NewBuddy(config)
			if err != nil {
				log.Fatalf("Unable to create certbuddy instance: %+v", err)
			}
			buddies = append(buddies, buddy)
		}

		for _, buddy := range buddies {
			if err := buddy.EnsureCerts(); err != nil {
				errc <- err
			}
		}

		// We want to run continously, for example in Docker
		if !*once {
			time.Sleep(time.Hour * 24)
			for _, buddy := range buddies {
				if err := buddy.EnsureCerts(); err != nil {
					errc <- err
				}
			}
		}
	}()

	shutdown(<-errc)
}

func buddyConfigFromFlags() (BuddyConfig, error) {
	var issueDomains []string
	if strings.Contains(*domains, ",") {
		issueDomains = strings.Split(*domains, ",")
	} else {
		issueDomains = make([]string, 1, 1)
		issueDomains[0] = *domains
	}

	buddyConfig := BuddyConfig{}
	buddyConfig.Email = *email
	buddyConfig.Domains = issueDomains
	buddyConfig.KeyPath = *keyPath
	buddyConfig.CertPath = *certPath
	buddyConfig.WebrootPath = *webrootPath
	buddyConfig.AccountKeyPath = *accountKeyPath
	buddyConfig.ServiceName = *serviceName
	buddyConfig.RegistryAddress = *consulAddr
	return buddyConfig, nil
}

func verifyFlags() error {
	if *config != "" {
		// We have to parse a config file
		return nil
	}
	for name, value := range flagNameMap {
		if *value == "" {
			return fmt.Errorf("The flag %s may not be empty", name)
		}
	}
	return nil
}

func shutdown(err error) {
	log.Fatalf("Fatal: %v", err)
}

func interrupt() error {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	return fmt.Errorf("%s", <-c)
}
