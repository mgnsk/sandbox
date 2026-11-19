# Run from anywhere: outside the dev shell, each command enters it.
DEV := $(if $(IN_NIX_SHELL),,nix develop -c)

SYSTEM := $(shell nix eval --raw --impure --expr builtins.currentSystem)

# A go test -run filter, e.g. make test RUN=HostPort
RUN ?=

NIX_FILES := flake.nix nix/*.nix nix/fixtures/*.nix

# The binary, with a link per program it runs as.
BIN := .build/go/bin
PROGRAMS = $(shell cat cmd/sandbox/programs)

.PHONY: test coverage build lint fmt

# Everything: the sandbox.nix evaluation check, the Go tests - the
# real-sandbox ones (e2e) against a fresh build of the sandbox - and lint.
# The real-sandbox tests need a host with unprivileged user namespaces;
# inside a sandbox they skip.
test:
	nix build --no-link .#checks.$(SYSTEM).project
	SANDBOX_BIN=$$(nix build --no-link --print-out-paths)/bin/sandbox \
		$(DEV) go test $(if $(RUN),-run '$(RUN)') ./...
	$(if $(RUN),,$(MAKE) lint)

# Line coverage of the Go code by its tests.
coverage:
	mkdir -p .build/go
	$(DEV) sh -c 'go test -coverpkg=./... -coverprofile=.build/go/cover.txt ./... && go tool cover -func=.build/go/cover.txt'

build:
	$(DEV) go build -o $(BIN)/sandbox ./cmd/sandbox
	for p in $(filter-out sandbox,$(PROGRAMS)); do ln -sf sandbox $(BIN)/$$p; done

lint:
	nix fmt -- --check $(NIX_FILES)
	$(DEV) sh -c 'test -z "$$(gofmt -l cmd internal e2e)" && go vet ./...'

fmt:
	$(DEV) gofmt -w cmd internal e2e
	nix fmt -- $(NIX_FILES)
