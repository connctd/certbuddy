VERSION=0.2

TAG=connctd/certbuddy\:$(VERSION)
TAG_LATEST=connctd/certbuddy\:latest

DOCKER=docker

.PHONY: image

compile:
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-arm .

docker: compile
	cp certbuddy-amd64 ./Docker/
	$(DOCKER) build -t $(TAG) -t $(TAG_LATEST) ./Docker
	rm ./Docker/certbuddy-amd64
