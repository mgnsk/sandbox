# Run from anywhere: outside the dev shell, each command enters it.
DEV := $(if $(IN_NIX_SHELL),,nix develop -c)

# Asked of nix only by the targets that use it, and once.
SYSTEM = $(eval SYSTEM := $$(shell nix eval --raw --impure --expr builtins.currentSystem))$(SYSTEM)

# A go test -run filter, e.g. make test RUN=HostPort
RUN ?=

NIX_FILES := flake.nix nix/*.nix nix/modules/*.nix nix/fixtures/*.nix demo/*/*.nix
SHELL_FILES := demo/entrypoint.sh nix/modules/agent-hooks/*.sh nix/etc/bashrc nix/etc/profile

BIN := .build/go/bin

.PHONY: list test race coverage build lint vuln vendor-hash options fmt demo demo-clean

.DEFAULT_GOAL := list

# The targets with a `## description` after their name.
list: ## List the commands
	@awk -F':.*## ' '/^[a-z-]+:.*## /{printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# The sandbox built from this checkout, for the real-sandbox tests (e2e).
SANDBOX_BIN = $$(nix build --no-link --print-out-paths .\#checks.$(SYSTEM).default)/bin/sandbox

# Everything: the checks of the configuration and its modules, the Go
# tests - the real-sandbox ones (e2e) against a fresh build of the sandbox -
# and lint. The real-sandbox tests need a host with
# unprivileged user namespaces; inside a sandbox they skip.
test: ## Nix checks, all Go tests (RUN=filter) and lint
	nix build --no-link .#checks.$(SYSTEM).modules .#checks.$(SYSTEM).config .#checks.$(SYSTEM).options
	SANDBOX_BIN=$(SANDBOX_BIN) $(DEV) go test $(if $(RUN),-run '$(RUN)') ./...
	$(if $(RUN),,$(MAKE) lint)

# The Go tests under the race detector. Not part of `make test`: the
# launcher's tests take minutes that way.
race: ## All Go tests under the race detector (RUN=filter)
	SANDBOX_BIN=$(SANDBOX_BIN) $(DEV) go test -race $(if $(RUN),-run '$(RUN)') ./...

# Line coverage of the Go code by its tests, the real-sandbox ones included
# where they run.
coverage: ## Line coverage of the Go code
	mkdir -p .build/go
	SANDBOX_BIN=$(SANDBOX_BIN) $(DEV) sh -c 'go test -coverpkg=./... -coverprofile=.build/go/cover.txt ./... && go tool cover -func=.build/go/cover.txt'

build: ## Build sandbox-bin into .build/go/bin
	$(DEV) go build -o $(BIN)/sandbox-bin ./cmd/sandbox-bin

# SC1091: what bashrc and profile source isn't there to follow.
lint: ## Check formatting, go vet, staticcheck, the workflows and shell files
	nix fmt -- --check $(NIX_FILES)
	$(DEV) sh -c 'test -z "$$(gofmt -l cmd internal e2e)" && go vet ./... && staticcheck ./...'
	$(DEV) sh -c 'actionlint && shellcheck -s bash -e SC1091 $(SHELL_FILES)'

# Known vulnerabilities in the Go toolchain and modules, as far as the code
# reaches them. Not part of test: what it finds is fixed by a newer nixpkgs
# or module, not by the change at hand. Needs the network (vuln.go.dev).
vuln: ## Known vulnerabilities the Go code reaches
	$(DEV) govulncheck ./...

# After a change to go.mod or go.sum: the hash of the modules nix builds
# the binary from, taken from the build that fails for the lack of it.
vendor-hash: ## Update nix/go.nix's vendorHash after a go.mod change
	sed -i 's|vendorHash = "[^"]*";|vendorHash = "";|' nix/go.nix
	hash=$$(nix build --no-link .#checks.$(SYSTEM).default 2>&1 | sed -n 's/^ *got: *//p'); \
		test -n "$$hash" && sed -i "s|vendorHash = \"\";|vendorHash = \"$$hash\";|" nix/go.nix
	nix build --no-link .#checks.$(SYSTEM).default

# After a change to an option: its type, default or description. `make
# test` fails while OPTIONS.md isn't what the declarations give.
options: ## Write OPTIONS.md from the option declarations
	cp --no-preserve=mode $$(nix build --no-link --print-out-paths .\#checks.$(SYSTEM).options.doc) OPTIONS.md

fmt: ## Format the Go and nix files
	$(DEV) gofmt -w cmd internal e2e
	nix fmt -- $(NIX_FILES)

# A shell as a fresh user, in a Debian container with multi-user nix, set
# up by demo/entrypoint.sh: a distribution of the sandbox (demo/distribution)
# installed with `nix profile add`, and a Go project to start it in - the
# sandbox as a new user meets it, from the remote (github:mgnsk/sandbox),
# not this checkout. Run on the host (no docker inside a sandbox). The nix
# store is kept in a volume between runs, the home isn't; make demo-clean
# drops the store, e.g. after changing demo/Dockerfile. A command instead of
# the shell: make demo ARGS='sandbox claude'
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
		-v $(DEMO_NIX_VOLUME):/nix \
		-v $(CURDIR):/src:ro \
		$(DEMO_IMAGE) $(ARGS)
endef

demo: ## Demo: a distribution of the sandbox, in a fresh container (ARGS='cmd')
	$(call demo)

demo-clean: ## Drop the demo's nix store volume
	docker volume rm -f $(DEMO_NIX_VOLUME)
