.PHONY: build test vet lint clean install

BINARY := secagent
MODULE := secagent

build:
	go build -o $(BINARY) .

install:
	go install .

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

clean:
	rm -f $(BINARY)

check: vet test

all: check build
