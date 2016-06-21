package main

import (
	"fmt"
	"github.com/hashicorp/consul/api"
	//"github.com/satori/go.uuid"
)

type ConsulNotifier struct {
	client    *api.Client
	ServiceId string
	checkId   string
}

func NewConsulNotifier(consulAddr string, serviceId string) (Notifier, error) {
	config := &api.Config{
		Address: consulAddr,
		Scheme:  "http",
	}
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &ConsulNotifier{
		client:    client,
		ServiceId: serviceId,
	}, nil
}

func (c *ConsulNotifier) RegisterCertsAvailable() error {

	c.checkId = fmt.Sprintf("%s-valid", c.ServiceId)

	checkRegistration := &api.AgentCheckRegistration{
		ID:        c.checkId,
		ServiceID: c.ServiceId,
		Name:      "HTTPs certificates available",
		AgentServiceCheck: api.AgentServiceCheck{
			TTL: "46800s", // 13 hours
		},
	}

	service := &api.AgentServiceRegistration{
		ID:   c.ServiceId,
		Name: c.ServiceId,
	}

	if err := c.client.Agent().ServiceRegister(service); err != nil {
		return err
	}

	return c.client.Agent().CheckRegister(checkRegistration)
}

func (c *ConsulNotifier) DeregisterCertsAvailable() error {
	if err := c.client.Agent().CheckDeregister(c.checkId); err != nil {
		return err
	}
	return c.client.Agent().ServiceDeregister(c.ServiceId)
}

func (c *ConsulNotifier) NotifyCertsAvailable() error {
	return c.client.Agent().UpdateTTL(c.checkId, "", "pass")
}

func (c *ConsulNotifier) NotifyCertsUnavailable() error {
	return c.client.Agent().UpdateTTL(c.checkId, "", "fail")
}

func (c *ConsulNotifier) NotifyCertsRenewed() error {
	// TODO find an elegant way to notify nginx via Consul about new certificates
	return nil
}
