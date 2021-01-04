GO_OS := $(shell go env GOOS)
GO_ARCH := $(shell go env GOARCH)
GO_FLAGS :=

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

.NOTPARALLEL:

all: clean deps test

.PHONY: clean
clean:
	@rm -f coverage.txt

.PHONY: deps
deps:
	@go get ./...

.PHONY: deps-clean
deps-clean:
	@go mod tidy

.PHONY: test
test:
	@./go-test.sh
