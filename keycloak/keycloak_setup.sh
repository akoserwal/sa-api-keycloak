#!/bin/bash

set -e

docker network create keycloak-network || true

docker run \
  --name=keycloak-sso \
  --net keycloak-network \
  -p $KEYCLOAK_PORT_NO:8080 \
  -e DB_VENDOR=h2  \
  -e KEYCLOAK_USER=${KEYCLOAK_USER} \
  -e KEYCLOAK_PASSWORD=${KEYCLOAK_PASSWORD} \
  -d quay.io/keycloak/keycloak:17.0.1-legacy
