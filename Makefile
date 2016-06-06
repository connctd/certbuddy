VERSION=0.1

TAG=connctd/letsencrypthelper\:$(VERSION)

DOCKER=docker

.PHONY: image

compile:
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o letsencrypthelper .

image: compile
	$(DOCKER) build -t $(TAG) ./Docker
