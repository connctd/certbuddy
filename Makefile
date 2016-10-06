VERSION=0.2

TAG=connctd/certbuddy\:$(VERSION)
TAG_LATEST=connctd/certbuddy\:latest
TAG_DEBUG=connctd/certbuddy:\latest-debug

DOCKER=docker

.PHONY: release debug clean docker/release docker/debug

release:
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-amd64 ./cmd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-arm ./cmd

debug:
	CGO_ENABLED=0 GOOS=linux go build -tags debug -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-debug-amd64 ./cmd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -tags debug -ldflags="-s -w" -a -installsuffix cgo -o certbuddy-debug-arm ./cmd

docker/release: release
	cp certbuddy-amd64 ./Docker/certbuddy
	$(DOCKER) build -t $(TAG) -t $(TAG_LATEST) ./Docker
	rm ./Docker/certbuddy

docker/debug: debug
	cp certbuddy-debug-amd64 ./Docker/certbuddy
	$(DOCKER) build -t $(TAG)-debug -t $(TAG_DEBUG) ./Docker
	rm ./Docker/certbuddy

clean:
	rm -f certbuddy*
