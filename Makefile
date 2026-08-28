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

.PHONY: all build test race vet fmt lint clean run tidy cover dist install-systemd

all: fmt vet test build

build:
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/mirage-director ./cmd/mirage-director
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/miragectl       ./cmd/miragectl
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/mirage-presence ./cmd/mirage-presence
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/mirage-breadcrumbs ./cmd/mirage-breadcrumbs
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

# Cross-compile release binaries for every supported platform into dist/.
# One statically-linked binary per OS/arch, no CGO, so a customer copies a file
# and runs it -- there is no runtime to install.
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64
DISTBINS  := mirage-director miragectl mirage-presence mirage-breadcrumbs

dist:
	@rm -rf dist && mkdir -p dist
	@for platform in $(PLATFORMS); do 	  os=$${platform%/*}; arch=$${platform#*/}; 	  ext=""; [ "$$os" = "windows" ] && ext=".exe"; 	  outdir=dist/mirage-$(VERSION)-$$os-$$arch; mkdir -p $$outdir; 	  for bin in $(DISTBINS); do 	    echo "  $$os/$$arch  $$bin$$ext"; 	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch 	      go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $$outdir/$$bin$$ext ./cmd/$$bin || exit 1; 	  done; 	  cp -r profiles README.md $$outdir/ 2>/dev/null || true; 	  ( cd dist && zip -qr mirage-$(VERSION)-$$os-$$arch.zip mirage-$(VERSION)-$$os-$$arch ); 	done
	@echo "release archives -> dist/"

# Install the director as a systemd service on this host (Linux).
install-systemd: build
	install -D -m0755 $(BIN)/mirage-director /usr/local/bin/mirage-director
	install -D -m0755 $(BIN)/miragectl /usr/local/bin/miragectl
	install -D -m0644 packaging/mirage-director.service /etc/systemd/system/mirage-director.service
	@echo "installed. Edit /etc/mirage/config.yaml, then: systemctl enable --now mirage-director"
