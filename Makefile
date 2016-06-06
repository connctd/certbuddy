VERSION=0.1

TAG=connctd/letsencrypthelper\:$(VERSION)

DOCKER=docker

.PHONY: image

compile:
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o letsencrypthelper-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -a -installsuffix cgo -o letsencrypthelper-arm .

image: compile
	$(DOCKER) build -t $(TAG) ./Docker
