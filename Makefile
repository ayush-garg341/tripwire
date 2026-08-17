BINARY  := tripwire
VERSION := $(shell grep -o 'version = "[^"]*"' main.go | cut -d'"' -f2)
FLAGS   := -trimpath -ldflags "-s -w"

.PHONY: all test vet build build-arm64 build-amd64 clean install

all: test build

test:
	go test ./...

vet:
	go vet ./...
	GOOS=linux go vet ./...

# Cross-compile from anywhere; the binary is static, with no libpcap and no
# libc dependency to satisfy on the target box.
build: build-arm64 build-amd64

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(FLAGS) -o dist/$(BINARY)-linux-arm64 .

build-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(FLAGS) -o dist/$(BINARY)-linux-amd64 .

# Run on the EC2 box itself, as root.
install:
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)
	install -d -m 0700 /var/lib/$(BINARY) /etc/$(BINARY)
	[ -f /etc/$(BINARY)/allow.txt ] || install -m 0644 deploy/allow.txt /etc/$(BINARY)/allow.txt
	install -m 0644 deploy/$(BINARY).service /etc/systemd/system/$(BINARY).service
	systemctl daemon-reload

clean:
	rm -rf dist
