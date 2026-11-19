# Run from anywhere: outside the dev shell, each command enters it.
DEV := $(if $(IN_NIX_SHELL),,nix develop -c)

SYSTEM := $(shell nix eval --raw --impure --expr builtins.currentSystem)

# A pytest -k filter, e.g. make test K=host_port
K ?=

NIX_FILES := flake.nix nix/*.nix tests/fixtures/*.nix

# The Go rewrite's binary, with a link per program it has.
GO_BIN := .build/go/bin
GO_PROGRAMS = $(shell cat cmd/sandbox/programs)

.PHONY: test test-go coverage coverage-go go-build lint fmt

# Everything: the sandbox.nix evaluation check, the whole pytest suite
# against a fresh build of the sandbox, and lint. The real-sandbox tests need
# a host with unprivileged user namespaces; inside a sandbox they skip.
test:
	nix build --no-link .#checks.$(SYSTEM).project
	SANDBOX_BIN=$$(nix build --no-link --print-out-paths)/bin/sandbox \
		$(DEV) pytest -v -rs $(if $(K),-k '$(K)') tests
	$(if $(K),,$(MAKE) lint)

# Line coverage of src/ by the pytest suite, programs it starts included.
coverage:
	$(DEV) pytest -q -p no:cacheprovider --cov --cov-report=term-missing:skip-covered $(if $(K),-k '$(K)') tests

# The whole suite, with the Go binary's programs in place of src/'s.
test-go: go-build
	SANDBOX_GUARD_CMD='$(CURDIR)/$(GO_BIN)/{name}' SANDBOX_LAUNCHER='$(CURDIR)/$(GO_BIN)/sandbox' \
		$(DEV) pytest -q -rs -p no:cacheprovider $(if $(K),-k '$(K)') tests

# Line coverage of the Go code by the same suite.
coverage-go: GO_COVER = -cover -covermode=atomic
coverage-go: go-build
	rm -rf .build/go/cover && mkdir -p .build/go/cover
	GOCOVERDIR=$(CURDIR)/.build/go/cover SANDBOX_GUARD_CMD='$(CURDIR)/$(GO_BIN)/{name}' SANDBOX_LAUNCHER='$(CURDIR)/$(GO_BIN)/sandbox' \
		$(DEV) pytest -q -p no:cacheprovider $(if $(K),-k '$(K)') tests
	$(DEV) sh -c 'go tool covdata textfmt -i=.build/go/cover -o=.build/go/cover.txt && go tool cover -func=.build/go/cover.txt'

go-build:
	$(DEV) go build $(GO_COVER) -o $(GO_BIN)/sandbox ./cmd/sandbox
	for p in $(filter-out sandbox,$(GO_PROGRAMS)); do ln -sf sandbox $(GO_BIN)/$$p; done

lint:
	$(DEV) sh -c 'ruff check . && ruff format --check .'
	nix fmt -- --check $(NIX_FILES)
	$(DEV) sh -c 'test -z "$$(gofmt -l cmd internal)" && go vet ./... && go test ./...'

fmt:
	$(DEV) ruff format .
	$(DEV) gofmt -w cmd internal
	nix fmt -- $(NIX_FILES)
