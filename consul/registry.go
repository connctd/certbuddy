package consul

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/connctd/certbuddy"
	"github.com/hashicorp/consul/api"
	"github.com/pkg/errors"
)

type ConsulRegistry struct {
	client      *api.Client
	ServiceName string
}

var DefaultTTL = "432000s" // 5 days

func NewConsulRegistry(consulAddr string, serviceName string) (certbuddy.Registry, error) {
	config := &api.Config{
		Address: consulAddr,
		Scheme:  "http",
	}
	client, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "Can't create Consul client")
	}
	_, err = client.Status().Leader()
	if err != nil {
		return nil, errors.Wrap(err, "Can't connect to consul node")
	}
	return &ConsulRegistry{
		client:      client,
		ServiceName: serviceName,
	}, nil
}

func (c *ConsulRegistry) CertAvailable(cert *x509.Certificate) error {
	serviceId := getServiceId(cert)

	checkId := getCheckId(cert)

	if err := c.client.Agent().PassTTL(checkId, "ok"); err != nil {
		checkReg := &api.AgentCheckRegistration{
			ID:        checkId,
			Name:      serviceId,
			Notes:     fmt.Sprintf("TTL check for TLS certificate %s", serviceId),
			ServiceID: serviceId,
			AgentServiceCheck: api.AgentServiceCheck{
				TTL: DefaultTTL,
			},
		}

		service := &api.AgentServiceRegistration{
			ID:   serviceId,
			Name: c.ServiceName,
		}

		if err := c.client.Agent().ServiceRegister(service); err != nil {
			return errors.Wrap(err, "Can't register service for TLS certificate")
		}

		if err := c.client.Agent().CheckRegister(checkReg); err != nil {
			return errors.Wrap(err, "Can't register check")
		}
	}

	return nil
}

func (c *ConsulRegistry) CertsExpired(cert *x509.Certificate) error {
	serviceId := getServiceId(cert)
	checkId := getCheckId(cert)

	if err := c.client.Agent().FailTTL(checkId, "fail"); err != nil {
		return errors.Wrap(err, "Failed to fail TTL check")
	}

	if err := c.client.Agent().ServiceDeregister(serviceId); err != nil {
		return errors.Wrap(err, "Can't deregister certificate service instance")
	}
	if err := c.client.Agent().CheckDeregister(checkId); err != nil {
		return errors.Wrap(err, "Can't deregister check for certificate")
	}
	return nil
}

func getServiceId(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Signature)
}

func getCheckId(cert *x509.Certificate) string {
	serviceId := getServiceId(cert)
	return fmt.Sprintf("%s-valid", serviceId)
}
