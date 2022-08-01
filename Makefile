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

DOCKER ?= docker
DOCKER_CONFIG="${PWD}/.docker"

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

version:=$(shell date +%s)
image_tag:=$(version)

external_image_registry:=default-route-openshift-image-registry.apps-crc.testing
internal_image_registry:=image-registry.openshift-image-registry.svc:5000
# Build the binary and image

NAMESPACE ?= service-account-api-${USER}

# The name of the image repository needs to start with the name of an existing
# namespace because when the image is pushed to the internal registry of a
# cluster it will assume that that namespace exists and will try to create a
# corresponding image stream inside that namespace. If the namespace doesn't
# exist the push fails. This doesn't apply when the image is pushed to a public
# repository, like `docker.io` or `quay.io`.
image_repository:=$(NAMESPACE)/service-account-api


image/build:
	$(DOCKER) --config="${DOCKER_CONFIG}" build -t "$(external_image_registry)/$(image_repository):$(image_tag)" .
.PHONY: image/build

docker/run:
	$(DOCKER) run -u $(shell id -u) --net keycloak-network --rm --name service-account-api -d -p 8000:8000 -e "keycloak_host=http://keycloak-sso:8180" -e "realm=redhat-external" -e "clientId=admin-service-account" -e "ENV secret=admin-service-account" default-route-openshift-image-registry.apps-crc.testing/service-account-api-akoserwa/service-account-api:1659100118
.PHONY: docker/run

