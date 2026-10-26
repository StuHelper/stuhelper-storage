GOWORK ?= off
export GOWORK

.PHONY: setup generate check-generated check test build
setup:
	LEFTHOOK=0 pnpm install --frozen-lockfile
generate:
	node scripts/generate.mjs
check-generated:
	node scripts/generate.mjs --check
check: check-generated
	test -n "$(STUHELPER_STORAGE_TEST_DSN)" || (echo 'Set STUHELPER_STORAGE_TEST_DSN to an isolated PostgreSQL test server'; exit 1)
	pnpm exec stuhelper-check repository
	node scripts/check-module.mjs
	pnpm exec stuhelper-check docs
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	go build ./...
	pnpm exec stuhelper-check workflows
test:
	test -n "$(STUHELPER_STORAGE_TEST_DSN)" || (echo 'Set STUHELPER_STORAGE_TEST_DSN to an isolated PostgreSQL test server'; exit 1)
	go test -race -count=1 ./...
build:
	go build ./...
