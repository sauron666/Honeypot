BIN      := bin
PKG      := ./...
GOFLAGS  ?=
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w \
  -X github.com/sauron666/Honeypot/internal/version.Version=$(VERSION) \
  -X github.com/sauron666/Honeypot/internal/version.Commit=$(COMMIT) \
  -X github.com/sauron666/Honeypot/internal/version.BuildDate=$(DATE)

export GOTOOLCHAIN := local

.PHONY: all build test race vet fmt lint clean run tidy cover

all: fmt vet test build

build:
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/mirage-director ./cmd/mirage-director
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/miragectl       ./cmd/miragectl
	@echo "built -> $(BIN)/"

test:
	go test $(PKG)

race:
	go test -race $(PKG)

cover:
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -1

vet:
	go vet $(PKG)

fmt:
	gofmt -l -w $(shell git ls-files '*.go' 2>/dev/null || find . -name '*.go')

tidy:
	go mod tidy

clean:
	rm -rf $(BIN) coverage.out

# Run the all-in-one honeypot on high ports, no privileges needed.
run: build
	$(BIN)/mirage-director --config profiles/p0-box.yaml
