#!/bin/bash
KEYCLOAK_URL="http://127.0.0.1:8180"
TOKEN_PATH="/auth/realms/redhat-external/protocol/openid-connect/token"

CLIENT_ID=admin-cli

KEYCLOAK_USER=test-user
KEYCLOAK_PASSWORD=test

RESULT=$(curl -sk --data "grant_type=password&client_id=$CLIENT_ID&username=$KEYCLOAK_USER&password=$KEYCLOAK_PASSWORD" "$KEYCLOAK_URL"$TOKEN_PATH)
TOKEN=$(jq -r '.access_token' <<< "$RESULT")
echo "$TOKEN"