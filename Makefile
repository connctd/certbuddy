VERSION=0.1

TAG=connctd/certbuddy\:$(VERSION)

DOCKER=docker

.PHONY: image

compile:
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-arm .

docker: compile
	cp certbuddy-amd64 ./Docker/
	$(DOCKER) build -t $(TAG) ./Docker
	rm ./Docker/certbuddy-amd64
