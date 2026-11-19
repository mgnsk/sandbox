# Run from anywhere: outside the dev shell, each command enters it.
DEV := $(if $(IN_NIX_SHELL),,nix develop -c)

SYSTEM := $(shell nix eval --raw --impure --expr builtins.currentSystem)

# A pytest -k filter, e.g. make test K=host_port
K ?=

NIX_FILES := flake.nix nix/*.nix tests/fixtures/*.nix

# The binary the tests run, with a link per program it runs as.
BIN := .build/go/bin
PROGRAMS = $(shell cat cmd/sandbox/programs)
COVER_DIR := .build/go/cover

.PHONY: test coverage build lint fmt

# Everything: the sandbox.nix evaluation check, the whole pytest suite
# against the binary and a fresh build of the sandbox, and lint. The
# real-sandbox tests need a host with unprivileged user namespaces; inside a
# sandbox they skip.
test: build
	nix build --no-link .#checks.$(SYSTEM).project
	SANDBOX_BIN=$$(nix build --no-link --print-out-paths)/bin/sandbox \
		$(DEV) pytest -v -rs $(if $(K),-k '$(K)') tests
	$(if $(K),,$(MAKE) lint)

# Line coverage of the Go code by the pytest suite.
coverage: COVER = -cover -covermode=atomic
coverage: build
	rm -rf $(COVER_DIR)
	mkdir -p $(COVER_DIR)
	GOCOVERDIR=$(CURDIR)/$(COVER_DIR) \
		$(DEV) pytest -q -p no:cacheprovider $(if $(K),-k '$(K)') tests
	$(DEV) sh -c 'go tool covdata textfmt -i=$(COVER_DIR) -o=.build/go/cover.txt && go tool cover -func=.build/go/cover.txt'

build:
	$(DEV) go build $(COVER) -o $(BIN)/sandbox ./cmd/sandbox
	for p in $(filter-out sandbox,$(PROGRAMS)); do ln -sf sandbox $(BIN)/$$p; done

lint:
	$(DEV) sh -c 'ruff check . && ruff format --check .'
	nix fmt -- --check $(NIX_FILES)
	$(DEV) sh -c 'test -z "$$(gofmt -l cmd internal)" && go vet ./... && go test ./...'

fmt:
	$(DEV) ruff format .
	$(DEV) gofmt -w cmd internal
	nix fmt -- $(NIX_FILES)
