#!/bin/bash
KEYCLOAK_URL="http://127.0.0.1:8180"
TOKEN_PATH="/auth/realms/redhat-external/protocol/openid-connect/token"

CLIENT_ID=admin-cli

KEYCLOAK_USER=test
KEYCLOAK_PASSWORD=test


RESULT=$(curl -sk --data "grant_type=password&client_id=$CLIENT_ID&username=$KEYCLOAK_USER&password=$KEYCLOAK_PASSWORD" "$KEYCLOAK_URL"$TOKEN_PATH)
echo $RESULT
export TOKEN=$(jq -r '.access_token' <<< "$RESULT")
echo "$TOKEN"

SA=$(curl -v POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/auth/realms/redhat-external/apis/service_accounts/v1 -d '{"name":"test", "description":"test"}')
echo $SA