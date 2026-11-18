# Run from anywhere: outside the dev shell, each command enters it.
DEV := $(if $(IN_NIX_SHELL),,nix develop -c)

SYSTEM := $(shell nix eval --raw --impure --expr builtins.currentSystem)

# A pytest -k filter, e.g. make test K=host_port
K ?=

NIX_FILES := flake.nix nix/*.nix tests/fixtures/*.nix

.PHONY: test coverage lint fmt

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

lint:
	$(DEV) sh -c 'ruff check . && ruff format --check .'
	nix fmt -- --check $(NIX_FILES)

fmt:
	$(DEV) ruff format .
	nix fmt -- $(NIX_FILES)
