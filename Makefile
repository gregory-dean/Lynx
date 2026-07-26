MODULE   := github.com/direo/lynx
BINARY   := lynx
VERSION  ?= 0.1.0
LDFLAGS  := -ldflags "-X github.com/direo/lynx/internal/cli.Version=$(VERSION)"

.PHONY: build test lint install clean cross-compile coverage

build:
	go build $(LDFLAGS) -o bin/$(BINARY)$(shell go env GOEXE) ./cmd/lynx

test:
	go test ./...

coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out

lint:
	go vet ./...
	go fmt ./...

install:
	go install $(LDFLAGS) ./cmd/lynx

clean:
	rm -rf bin dist coverage.out coverage.html

cross-compile:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 ./cmd/lynx
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64 ./cmd/lynx
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe ./cmd/lynx
