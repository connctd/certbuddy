package main

type Notifier interface {
	RegisterCertsAvailable() error
	DeregisterCertsAvailable() error
	NotifyCertsAvailable() error
	NotifyCertsUnavailable() error
	NotifyCertsRenewed() error
}
