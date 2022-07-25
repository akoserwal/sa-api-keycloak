# Requires golangci-lint to be installed @ $(go env GOPATH)/bin/golangci-lint
# https://golangci-lint.run/usage/install/

GO := go
GOFMT := gofmt
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell $(GO) env GOBIN))
GOBIN=$(shell $(GO) env GOPATH)/bin
else
GOBIN=$(shell $(GO) env GOBIN)
endif

lint:
	golangci-lint run ./...
.PHONY: lint

generate:
	./scripts/generate.sh
.PHONY: generate

binary:
	$(GO) build ./cmd/service-account-api
.PHONY: binary

KEYCLOAK_URL ?= http://localhost:8180
KEYCLOAK_PORT_NO ?= 8180
KEYCLOAK_USER ?= admin
KEYCLOAK_PASSWORD ?= admin

sso/setup:
	KEYCLOAK_PORT_NO=$(KEYCLOAK_PORT_NO) KEYCLOAK_USER=$(KEYCLOAK_USER) KEYCLOAK_PASSWORD=$(KEYCLOAK_PASSWORD) ./keycloak/keycloak_setup.sh
.PHONY: sso/setup

sso/config:
	KEYCLOAK_URL=$(KEYCLOAK_URL) KEYCLOAK_USER=$(KEYCLOAK_USER) \
	KEYCLOAK_PASSWORD=$(KEYCLOAK_PASSWORD) ./keycloak/keycloak_config.sh
.PHONY: sso/config

sso/teardown:
	./keycloak/keycloak_teardown.sh
.PHONY: sso/teardown