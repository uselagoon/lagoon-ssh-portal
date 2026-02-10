# local development targets

.PHONY: test
test: mod-tidy generate
	go test -v ./...

.PHONY: mod-tidy
mod-tidy:
	go mod tidy

.PHONY: generate
generate: mod-tidy
	go generate ./...

.PHONY: build
build:
	# build a binary for the local architecture only
	goreleaser build --verbose --clean --single-target --snapshot

.PHONY: release-snapshot
release-snapshot:
	# build binaries for all architectures, and multi-arch docker images, but
	# don't validate or publish anything
	GITHUB_REPOSITORY=uselagoon goreleaser release --verbose --clean --snapshot

.PHONY: lint
lint:
	golangci-lint run

.PHONY: fuzz
fuzz: mod-tidy generate
	go test -fuzz='^Fuzz' -fuzztime=10s -v ./internal/server

.PHONY: cover
cover: mod-tidy generate
	go test -count=1 -v -covermode=atomic -coverprofile=cover.out -coverpkg=./... ./...
	go tool cover -html=cover.out
