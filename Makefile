# local development targets

.PHONY: test
test: mod-tidy generate
	go test -v ./...

.PHONY: mod-tidy
mod-tidy: generate
	go mod tidy

.PHONY: generate
generate:
	go generate ./...
