BIN := $(shell pwd)/bin
VERSION ?= $(shell git rev-parse --short HEAD)
GO?=$(shell which go)
export GOBIN := $(BIN)
export PATH := $(BIN):$(PATH)

BUILD_CMD := $(GO) install -ldflags "-X main.build=${VERSION}"



.PHONY: build/docker
build/docker: ## Build the docker image.
	DOCKER_BUILDKIT=1 \
	docker build \
		-f ./Dockerfile \
		-t 0xpolygon/verifier-backend:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` \


## install code generator for API files.
$(BIN)/oapi-codegen: tools.go go.mod go.sum
	go get github.com/deepmap/oapi-codegen/cmd/oapi-codegen
	$(GO) install github.com/deepmap/oapi-codegen/cmd/oapi-codegen

# install golang lint.
$(BIN)/golangci-lint: go.mod go.sum
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint


## Generate API files
.PHONY: api
api: $(BIN)/oapi-codegen
	$(BIN)/oapi-codegen -config ./api/config-oapi-codegen.yaml ./api/api.yaml > ./internal/api/api.gen.go


.PHONY: lint
lint: $(BIN)/golangci-lint
	  $(BIN)/golangci-lint run