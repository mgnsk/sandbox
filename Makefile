# Run from anywhere: outside the dev shell, each command enters it.
DEV := $(if $(IN_NIX_SHELL),,nix develop -c)

SYSTEM := $(shell nix eval --raw --impure --expr builtins.currentSystem)

# A go test -run filter, e.g. make test RUN=HostPort
RUN ?=

NIX_FILES := flake.nix nix/*.nix nix/fixtures/*.nix demo/*/*.nix

BIN := .build/go/bin

.PHONY: list test coverage build lint fmt demo-flake demo-home-manager demo-clean

.DEFAULT_GOAL := list

# The targets with a `## description` after their name.
list: ## List the commands
	@awk -F':.*## ' '/^[a-z-]+:.*## /{printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Everything: the sandbox.nix evaluation check, the Go tests - the
# real-sandbox ones (e2e) against a fresh build of the sandbox - and lint.
# The real-sandbox tests need a host with unprivileged user namespaces;
# inside a sandbox they skip.
test: ## Nix checks, all Go tests (RUN=filter) and lint
	nix build --no-link .#checks.$(SYSTEM).project
	SANDBOX_BIN=$$(nix build --no-link --print-out-paths .#checks.$(SYSTEM).default)/bin/sandbox \
		$(DEV) go test $(if $(RUN),-run '$(RUN)') ./...
	$(if $(RUN),,$(MAKE) lint)

# Line coverage of the Go code by its tests.
coverage: ## Line coverage of the Go code
	mkdir -p .build/go
	$(DEV) sh -c 'go test -coverpkg=./... -coverprofile=.build/go/cover.txt ./... && go tool cover -func=.build/go/cover.txt'

build: ## Build sandbox-bin into .build/go/bin
	$(DEV) go build -o $(BIN)/sandbox-bin ./cmd/sandbox-bin

lint: ## Check formatting and go vet
	nix fmt -- --check $(NIX_FILES)
	$(DEV) sh -c 'test -z "$$(gofmt -l cmd internal e2e)" && go vet ./...'

fmt: ## Format the Go and nix files
	$(DEV) gofmt -w cmd internal e2e
	nix fmt -- $(NIX_FILES)

# A shell as a fresh user, in a Debian container with multi-user nix, in a
# demo set up by demo/entrypoint.sh - the sandbox as a new user meets it,
# from the remote (github:mgnsk/sandbox), not this checkout:
#   demo-flake          `nix run github:mgnsk/sandbox`, in a project whose
#                       flake.nix and sandbox.nix bring and shape everything
#   demo-home-manager   programs.sandbox in the user's home-manager config
# Run on the host (no docker inside a sandbox). The nix store is kept in a
# volume between runs, the home isn't; make demo-clean drops the store, e.g.
# after changing demo/Dockerfile. A command instead of the shell:
# make demo-flake ARGS='sandbox nix develop -c claude'
DEMO_IMAGE := sandbox-demo
DEMO_NIX_VOLUME := sandbox-demo-nix
ARGS ?=

# The sandbox needs user namespaces (seccomp), a fresh /proc (systempaths)
# and a tun device for pasta, which docker's defaults all deny. /src gives
# the entrypoint the demo files.
define demo
	docker build -t $(DEMO_IMAGE) demo
	docker run --rm -it \
		--security-opt seccomp=unconfined \
		--security-opt apparmor=unconfined \
		--security-opt systempaths=unconfined \
		--device /dev/net/tun \
		-e DEMO=$(1) \
		-v $(DEMO_NIX_VOLUME):/nix \
		-v $(CURDIR):/src:ro \
		$(DEMO_IMAGE) $(ARGS)
endef

demo-flake: ## Demo: a project with flake.nix and sandbox.nix (ARGS='cmd')
	$(call demo,flake)

demo-home-manager: ## Demo: the sandbox from home-manager (ARGS='cmd')
	$(call demo,home-manager)

demo-clean: ## Drop the demo's nix store volume
	docker volume rm -f $(DEMO_NIX_VOLUME)
