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

.PHONY: all build test lint licenses fmt clean

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

# Lint gate, pinned like CI: the workflow's GOLANGCI_LINT_VERSION is the one
# version this repo lints under, and a mismatch has bitten before - the local
# linter once reported zero issues while CI's stricter version failed the
# release. The guard fails fast instead of silently linting under a different
# version; GNU make 4.4 makes each line .SHELLSTATUS-visible, so the check
# cannot pass silently.
lint:
	@want="$$(sed -n 's/^[[:space:]]*GOLANGCI_LINT_VERSION:[[:space:]]*v\{0,1\}\(.*\)$$/\1/p' .github/workflows/ci.yml | head -1)"; \
	have="golangci-lint $$(golangci-lint version 2>/dev/null | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p')"; \
	if [ -z "$$want" ]; then echo "lint: GOLANGCI_LINT_VERSION not found in .github/workflows/ci.yml" >&2; exit 1; fi; \
	if [ "$$have" != "golangci-lint $$want" ]; then \
		echo "lint: linter mismatch: have '$$have', CI pins '$$want'" >&2; \
		echo "  install it: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$$want" >&2; \
		exit 1; \
	fi
	golangci-lint run
	go tool templ fmt -fail .

# Rebuild the generated license bundle under licenses/; CI gates it by diffing.
licenses:
	GOTOOLCHAIN=$(GOTOOLCHAIN) ./hack/licenses.sh

# Format Go code and templ templates.
fmt:
	gofmt -w cmd internal
	go tool templ fmt .

clean:
	rm -rf build
