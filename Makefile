# SPDX-License-Identifier: GPL-3.0-or-later
# `check` is hermetic so the pre-commit hook can run it on every commit;
# `check/full` adds the container suites.

.DEFAULT_GOAL := help

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

# Git-ignored scratch for the build assertion, the drift check and the
# provisioning files; targets that write here order it.
SCRATCH := .cache/scratch
$(SCRATCH):
	@mkdir -p $@
TMPDIR_BASE := $(patsubst %/,%,$(if $(TMPDIR),$(TMPDIR),/tmp))
# Keyed on the worktree name, so lanes in separate worktrees do not share a farm.
TREE := $(notdir $(CURDIR))
FARM := $(TMPDIR_BASE)/ansible-tailscale/$(TREE)
COLLECTION := $(FARM)/ansible_collections/abn/tailscale
UV := uv run --no-sync --locked
SPEC := tests/fixtures/openapi/tailscale.yaml
SPEC_URL := https://api.tailscale.com/api/v2?outputOpenapiSchema=true

# Listed explicitly, so the farm cannot accumulate stale files that get linted.
COLLECTION_CONTENT := galaxy.yml meta plugins tests changelogs docs README.md LICENSE

ANSIBLE_TEST := ansible-test
GALAXY_BUILD := ansible-galaxy
CONTRIB := .contrib/scripts

.PHONY: init sync lane-setup collection/link \
  check check/full lint fmt test sanity integration live-smoke live-stress \
  build docs/lint docs/build docs/capabilities docs/capabilities/check changelog/lint spec/drift \
  live/tailnet oauth/probe oauth/client \
  hooks/install hooks/uninstall clean help

##@ Bootstrap

init: ## Install toolchain, hooks, and external validators
	@printf '\n  Installing Go-based validators (okf)\n'
	@GOBIN=$${GOBIN:-$$HOME/.local/bin} GOTOOLCHAIN=auto go install github.com/okfcli/okf/cmd/okf@latest
	@printf '\n  Syncing Python tooling environment\n'
	uv sync --locked
	@printf '\n  Installing pre-commit hooks\n'
	$(UV) pre-commit install
	@printf '\n  Materializing the collection path ansible-test requires\n'
	@$(MAKE) --no-print-directory collection/link
	@printf '\n  Ready. Run `make check`.\n\n'

sync: ## Refresh the locked Python tooling environment
	uv sync --locked

# A fresh worktree has no .venv, and `uv run --no-sync` needs one.
lane-setup: sync collection/link ## Prepare this worktree to run the gates
	@printf '  worktree ready. Run make check.\n\n'

# ansible-test enumerates through git, so a tree inside this repository, or a
# symlink, reports "All targets skipped" and checks nothing.
collection/link: ## Stage the collection where ansible-test requires it
	@rm -rf $(COLLECTION)
	@mkdir -p $(COLLECTION)
	@cp -a $(COLLECTION_CONTENT) $(COLLECTION)/
	@printf '  staged %s\n' '$(COLLECTION)'

##@ Quality gates

check: lint changelog/lint docs/lint docs/capabilities/check ## Fast hermetic gates: hooks, lint, changelog, docs (no containers)
	$(UV) pre-commit run --all-files
	@printf '\n  check: OK\n'

check/full: check sanity test integration ## Everything CI runs, including containerised suites

lint: collection/link ## Lint without autofixing
	$(UV) ruff check --no-fix .
	@printf '\n  ty\n'
	# The farm, not $(COLLECTION): an import of ansible_collections.abn.tailscale
	# resolves only against the directory that *contains* ansible_collections.
	$(UV) ty check --extra-search-path $(FARM)
	@printf '\n  ansible-lint\n'
	$(UV) ansible-lint

fmt: ## Apply formatting and safe lint fixes
	$(UV) ruff check --fix .
	$(UV) ruff format .
	@printf '\n  formatting applied. Re-run `make check`.\n'

##@ Tests

# `--docker` fails on this host and `--local` has no pytest, so the default mode,
# which bootstraps its own venv, is the local path. CI isolates with containers.
ANSIBLE_TEST_LOCAL := --python 3.12 --requirements --color yes

sanity: collection/link ## ansible-test sanity (validate-modules, pep8, pylint, import, ...)
	cd $(COLLECTION) && $(ANSIBLE_TEST) sanity --color yes

test: collection/link ## Unit tests
	cd $(COLLECTION) && $(ANSIBLE_TEST) units $(ANSIBLE_TEST_LOCAL)

integration: collection/link ## Integration tests
	cd $(COLLECTION) && $(ANSIBLE_TEST) integration $(ANSIBLE_TEST_LOCAL)

##@ Build and docs

# Two checks: no git-ignored path ships in the artifact, and no tracked path is
# declared in build_ignore. Both derive from git and galaxy.yml, so a new
# development path needs no change here.
build: | $(SCRATCH) ## Build the Galaxy artifact and assert its contents
	@rm -rf build
	$(GALAXY_BUILD) collection build --force --output-path build/
	@printf '\n  verifying artifact contents\n'
	@tar tzf build/*.tar.gz | sort -u > $(SCRATCH)/artifact.txt
	@git ls-files --others --ignored --exclude-standard --directory \
		| sort -u > $(SCRATCH)/ignored.txt
	@uv run --no-sync python -c "import sys, yaml; \
print('\n'.join(yaml.safe_load(open('galaxy.yml'))['build_ignore']))" \
		> $(SCRATCH)/excluded.txt
	@: > $(SCRATCH)/leaked.txt
	@grep -F -f $(SCRATCH)/ignored.txt $(SCRATCH)/artifact.txt \
		>> $(SCRATCH)/leaked.txt < /dev/null || true
	@uv run --no-sync python .contrib/scripts/assert-excluded.py $(SCRATCH) \
		>> $(SCRATCH)/leaked.txt || true
	@if [ -s $(SCRATCH)/leaked.txt ]; then \
		printf '\n  BUILD LEAKED development paths. Ignore them in git or galaxy.yml:\n'; \
		sed 's|^|    |' $(SCRATCH)/leaked.txt; \
		exit 1; \
	fi; \
	size=$$(du -m build/*.tar.gz | cut -f1); \
	if [ "$$size" -gt 20 ]; then \
		printf '\n  BUILD is %s MB, over the 20 MB Galaxy limit\n' "$$size"; exit 1; \
	fi; \
	printf '  artifact clean, %s MB\n\n' "$$size"

# Overridable so CI can pin the linter via uvx without installing the dev lock.
ANTSIBULL_DOCS ?= $(UV) antsibull-docs

docs/lint: ## Lint collection documentation
	$(ANTSIBULL_DOCS) lint-collection-docs . --plugin-docs --skip-rstcheck --no-check-extra-docs-refs

docs/build: ## Build the HTML docsite into built-docs/
	@mkdir -p built-docs
	cd built-docs && $(UV) antsibull-docs sphinx-init --use-current --squash-hierarchy \
		abn.tailscale --dest-dir . --fail-on-error
	@printf '\n  docsite build scaffolded in built-docs/\n'

docs/capabilities: ## Regenerate docs/capabilities.md from the code
	@$(UV) python .contrib/scripts/render-capabilities.py

docs/capabilities/check: ## Fail if docs/capabilities.md is out of step with the code
	@$(UV) python .contrib/scripts/render-capabilities.py --check
	@printf '  capabilities page: in step\n'

changelog/lint: ## Lint changelog fragments
	$(UV) antsibull-changelog lint

# The only sanctioned route to a real tailnet: a credential being present is not
# enough, so an explicit acknowledgement is required. The test OAuth secret is
# exchanged for a short-lived token, held only in the environment.
LIVE_ACK := I_HAVE_A_THROWAWAY_TAILNET
TS_OAUTH ?= .tskey-oauth
TS_API_BASE := https://api.tailscale.com/api/v2

# Serialises live runs on this machine. Development tooling only: it protects
# nothing on another machine, where it is absent.
LIVE_LOCK := .contrib/scripts/live-lock.sh

# PYTHONPATH is the farm, because the live tests import the collection by its
# absolute ansible_collections path.
# Extra flags for the live suites, such as `-k` or `-v`. Paths go in
# LIVE_PYTEST_FILES: the file list is appended after these flags, so a path given
# here would add to the glob rather than narrow it.
LIVE_PYTEST_ARGS ?=

# The files the stress suite runs, overriding the glob; empty means all of them.
LIVE_PYTEST_FILES ?=

live-stress: collection/link ## Full CRUD stress on a real tailnet, serialised by a dev-only machine lock
	@if [ "$${TS_LIVE_SMOKE:-}" != "$(LIVE_ACK)" ]; then \
		printf '\n  live stress refused.\n'; \
		printf '  Set TS_LIVE_SMOKE=%s to proceed,\n' '$(LIVE_ACK)'; \
		printf '  and only against a tailnet you are willing to discard.\n\n'; \
		exit 1; \
	fi; \
	[ -r "$(TS_KEY_FILE)" ] || { \
		printf '\n  no key at %s. Put an admin API key there, readable only by you,\n' '$(TS_KEY_FILE)'; \
		printf '  or set TS_KEY_FILE to its path.\n\n'; exit 1; }; \
	printf '\n  stress suite: key from %s\n' '$(TS_KEY_FILE)'; \
	export TS_KEY_FILE; \
	TS_TAILNET=$$(sed -n 1p $(TS_TAILNET_FILE) 2>/dev/null || true); export TS_TAILNET; \
	if [ -n "$(LIVE_PYTEST_FILES)" ]; then set -- $(LIVE_PYTEST_FILES); \
	else set -- $$(ls tests/live/test_*_module_live.py 2>/dev/null); fi; \
	if [ "$$#" -eq 0 ]; then printf '\n  no stress modules selected\n\n'; exit 1; fi; \
	PYTHONPATH=$(FARM) $(LIVE_LOCK) $(UV) pytest -m live_smoke -p no:cacheprovider $(LIVE_PYTEST_ARGS) "$$@"

live-smoke: collection/link ## Run the live suite (ack required), serialised by a dev-only machine lock
	@if [ "$${TS_LIVE_SMOKE:-}" != "$(LIVE_ACK)" ]; then \
		printf '\n  live smoke refused.\n'; \
		printf '  Set TS_LIVE_SMOKE=%s to proceed,\n' '$(LIVE_ACK)'; \
		printf '  and only against a tailnet you are willing to discard.\n\n'; \
		exit 1; \
	fi; \
	if [ -r "$(TS_OAUTH)" ]; then \
		printf '\n  using the test OAuth credential\n'; \
		cid=$$(sed -n 1p "$(TS_OAUTH)"); sec=$$(sed -n 2p "$(TS_OAUTH)"); \
		TS_API_TOKEN=$$(curl -sS --max-time 30 -X POST \
			-H 'Content-Type: application/x-www-form-urlencoded' \
			--data-urlencode "client_id=$$cid" --data-urlencode "client_secret=$$sec" \
			--data-urlencode 'grant_type=client_credentials' \
			'$(TS_API_BASE)/oauth/token' | jq -er .access_token) || exit 1; \
	elif [ -r "$(TS_KEY_FILE)" ]; then \
		printf '\n  using the personal API token, which carries every permission its owner has\n'; \
		TS_API_TOKEN=$$(cat "$(TS_KEY_FILE)"); \
	else \
		printf '\n  no credential found\n\n'; exit 1; \
	fi; \
	export TS_API_TOKEN; \
	export TS_TAILNET; \
	TS_OAUTH_CLIENT_ID=$$(sed -n 1p $(TS_OAUTH)); \
	export TS_OAUTH_CLIENT_ID; \
	TS_OAUTH_CLIENT_SECRET=$$(sed -n 2p $(TS_OAUTH)); \
	export TS_OAUTH_CLIENT_SECRET; \
	PYTHONPATH=$(FARM) $(LIVE_LOCK) $(UV) pytest -m live_smoke $(LIVE_PYTEST_ARGS) tests/live

##@ Upstream drift

# Tailscale states the OpenAPI spec is unstable and may change without notice.
spec/drift: | $(SCRATCH) ## Re-fetch the upstream OpenAPI spec and show what moved
	@$(CONTRIB)/spec-drift.sh '$(SPEC)' '$(SPEC_URL)' '$(SCRATCH)'

##@ Hooks

hooks/install: ## Install the pre-commit hook
	$(UV) pre-commit install

hooks/uninstall: ## Remove the pre-commit hook
	$(UV) pre-commit uninstall

##@ Utilities

clean: ## Remove build and test output
	rm -rf build/ built-docs/ tests/output/ .cache/ .ruff_cache/ .pytest_cache/ .ansible/
	rm -rf $(FARM)
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# Provisioning the test OAuth client, and the tailnet ID an OAuth token cannot
# discover for itself. These are the only recipes that touch a personal
# credential, and they belong to the coordinator.
TS_KEY_FILE ?= .tskey
OAUTH_CLIENT_NAME := ansible-collection-abn-tailscale
# `all`, because the collection manages nearly every resource, Tailscale extends
# an existing scope to new APIs, and it is the only scope that grants device tags
# without selecting them at creation.
OAUTH_SCOPES := all
TS_TAILNET_FILE ?= .tailnet-id
TS_TAILNET ?= $(shell cat $(TS_TAILNET_FILE) 2>/dev/null || echo -)

# The values .contrib/scripts/provision.sh reads from the environment.
PROVISION_ENV := TS_API_BASE='$(TS_API_BASE)' LIVE_ACK='$(LIVE_ACK)' \
	TS_KEY_FILE='$(TS_KEY_FILE)' TS_OAUTH='$(TS_OAUTH)' \
	TS_TAILNET_FILE='$(TS_TAILNET_FILE)' OAUTH_CLIENT_NAME='$(OAUTH_CLIENT_NAME)' \
	OAUTH_SCOPES='$(OAUTH_SCOPES)' TS_TAILNET='$(TS_TAILNET)'

.PHONY: live/tailnet oauth/probe oauth/client

live/tailnet: | $(SCRATCH) ## Record the tailnet ID, for playbooks managing more than one
	@$(PROVISION_ENV) $(CONTRIB)/provision.sh tailnet '$(SCRATCH)'

oauth/probe: | $(SCRATCH) ## Exchange the client secret, then report what the token reaches
	@$(PROVISION_ENV) $(CONTRIB)/provision.sh probe '$(SCRATCH)'

oauth/client: | $(SCRATCH) ## Mint the test OAuth client, or re-scope the existing one
	@$(PROVISION_ENV) $(CONTRIB)/provision.sh client '$(SCRATCH)'

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
	  /^[a-zA-Z0-9_/-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
