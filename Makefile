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
