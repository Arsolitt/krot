# Krot Makefile.
#
# Toolchain note: the pinned go-json-experiment alias (via cheburbox) requires
# exactly go1.26.4; go1.27 renamed the stdlib jsonv2 symbols it aliases. The
# GOTOOLCHAIN=go1.26.4 below (an env override that beats go.mod and survives
# go mod tidy) selects 1.26.4 regardless of the locally installed Go.
#
# krot-cp links cheburbox/sing-box option types (renderer + link
# builders); krot-agent additionally validates configs out-of-process
# via the sing-box binary, so neither needs protocol build tags.

CGO_ENABLED ?= 0

GOTOOLCHAIN ?= go1.26.4
LDFLAGS     := -s -w
VERSION     ?= dev

.PHONY: all build test lint fmt clean

all: build

# Generate templ sources and build both binaries into ./build/.
build:
	go tool templ generate ./internal/web
	mkdir -p build
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -trimpath -ldflags '$(LDFLAGS) -X main.version=$(VERSION)' -o build/krot-agent ./cmd/krot-agent
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -trimpath -ldflags '$(LDFLAGS)' -o build/krot-cp ./cmd/krot-cp

# Test suite. Store tests need a scratch PostgreSQL via
# KROT_TEST_DATABASE_URL; they skip when it is unset.
test:
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go test ./...

lint:
	golangci-lint run
	go tool templ fmt -fail .

# Format Go code and templ templates.
fmt:
	gofmt -w cmd internal
	go tool templ fmt .

clean:
	rm -rf build
