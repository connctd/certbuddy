package main

import (
	"fmt"
	"github.com/hashicorp/consul/api"
	//"github.com/satori/go.uuid"
)

var (
	ConsulClient *api.Client
	serviceId    string
	checkId      = "https-certs-valid"
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

	checkId = fmt.Sprintf("%s-valid", serviceName)
	//serviceId = uuid.NewV4().String()
	//checkId = uuid.NewV4().String()

	checkRegistration := &api.AgentCheckRegistration{
		ID:        checkId,
		ServiceID: serviceId,
		Name:      "HTTPs certificates available",
		AgentServiceCheck: api.AgentServiceCheck{
			TTL: "46800s", // 13 hours
		},
	}

	service := &api.AgentServiceRegistration{
		ID:   serviceName,
		Name: serviceName,
	}

	if err := ConsulClient.Agent().ServiceRegister(service); err != nil {
		return err
	}

	return ConsulClient.Agent().CheckRegister(checkRegistration)
}

func DeregisterCertsAvailable() error {
	if ConsulClient == nil {
		return nil
	}
	if err := ConsulClient.Agent().CheckDeregister(checkId); err != nil {
		return err
	}
	return ConsulClient.Agent().ServiceDeregister(serviceId)
}

func KeepCertsAvailableAlive(note string) error {
	if ConsulClient == nil {
		return nil
	}
	return ConsulClient.Agent().UpdateTTL(checkId, note, "pass")
}

func FailCertsAvailable(note string) error {
	if ConsulClient == nil {
		return nil
	}
	return ConsulClient.Agent().UpdateTTL(checkId, note, "fail")
}
