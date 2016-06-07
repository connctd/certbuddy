package main

import (
	"github.com/hashicorp/consul/api"
	"github.com/satori/go.uuid"
)

var (
	ConsulClient *api.Client
	serviceId    string
)

func ConnectConsul(addr string) error {

	config := &api.Config{
		Address: addr,
		Scheme:  "http",
	}
	var err error
	ConsulClient, err = api.NewClient(config)
	return err
}

func RegisterCertsAvailable(serviceName string) error {
	if ConsulClient == nil {
		return nil
	}
	if serviceName == "" {
		serviceName = "https-certs"
	}

	serviceId = uuid.NewV4().String()
	check := &api.AgentServiceCheck{
		TTL: "13h",
	}

	service := &api.AgentServiceRegistration{
		ID:    serviceId,
		Name:  serviceName,
		Check: check,
	}

	return ConsulClient.Agent().ServiceRegister(service)
}

func DeregisterCertsAvailable() error {
	if ConsulClient == nil {
		return nil
	}
	return ConsulClient.Agent().ServiceDeregister(serviceId)
}

func KeepCertsAvailableAlive(note string) error {
	if ConsulClient == nil {
		return nil
	}
	return ConsulClient.Agent().UpdateTTL(serviceId, note, "pass")
}

func FailCertsAvailable(note string) error {
	if ConsulClient == nil {
		return nil
	}
	return ConsulClient.Agent().UpdateTTL(serviceId, note, "fail")
}
