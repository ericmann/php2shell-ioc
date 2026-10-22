# php2shell-ioc: common tasks. Everything that runs code does so in Docker.

SCRIPT := php2shell-ioc.sh
SHELL_FILES := $(SCRIPT) tests/run.sh tests/lib.sh tests/cases/*.sh demo/*.sh

.PHONY: help lint test demo cast checksum check

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

lint: ## shellcheck everything as POSIX sh
	shellcheck -s sh -S warning $(SHELL_FILES)

test: ## run the test suite across the shell/image matrix (needs Docker)
	sh tests/run.sh

demo: ## watch the scanner catch planted indicators in a throwaway container
	sh demo/run.sh

cast: ## re-record docs/demo.cast and render docs/demo.gif (needs Docker + agg)
	python3 demo/record.py docs/demo.cast
	agg --idle-time-limit 2 --fps-cap 8 --font-size 14 --theme monokai docs/demo.cast docs/demo.gif

checksum: ## print the SHA-256 to publish alongside a release
	@sha256sum $(SCRIPT)

check: lint test ## lint + test (what CI runs)
