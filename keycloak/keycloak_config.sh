#!/bin/bash

TOKEN_PATH="/auth/realms/master/protocol/openid-connect/token"

CLIENT_ID=admin-cli


# wait for keycloak container to be up or timeout after 2 minutes
ERR_MESSAGE="Keycloak server not running at localhost:8180. No realm configuration will be applied"
timeout 120 bash -c 'while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' http://localhost:8180/auth/realms/master)" != "200" ]]; do echo "Waiting for keycloak server at localhost:8180"; sleep 10; done' || echo "$ERR_MESSAGE"

RESULT=$(curl -sk --data "grant_type=password&client_id=$CLIENT_ID&username=$KEYCLOAK_USER&password=$KEYCLOAK_PASSWORD" "$KEYCLOAK_URL"$TOKEN_PATH)
TOKEN=$(jq -r '.access_token' <<< "$RESULT")
echo "$TOKEN"

CREATE_REALM_RHOAS=$(curl -sk --data-raw '{"enabled":true,"id":"redhat-external","realm":"redhat-external"}' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms)
echo "$CREATE_REALM_RHOAS"
echo "Realm rhoas"


CREATE=$(curl -sk --data-raw '{
   "authorizationServicesEnabled": false,
   "clientId": "admin-service-account",
   "description": "admin-service-account",
   "name": "kas-fleet-manager",
   "secret":"admin-service-account",
    "directAccessGrantsEnabled": false,
    "serviceAccountsEnabled": true,
    "publicClient": false,
    "protocol": "openid-connect"
}' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/clients)
echo "$CREATE"

RE=$(curl -sk --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/clients?clientId=realm-management)
realmMgmtClientId=$(jq -r '.[].id' <<< "$RE")
echo "$realmMgmtClientId"


ROLES=$(curl -sk --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/clients/"$realmMgmtClientId"/roles)
manageUser=$(jq -c '.[] | select( .name | contains("manage-users")).id' <<< "$ROLES")
manageClients=$(jq -c '.[] | select( .name | contains("manage-clients")).id' <<< "$ROLES")
manageRealm=$(jq -c '.[] | select( .name | contains("manage-realm")).id' <<< "$ROLES")
echo "$manageUser"
echo "$manageRealm"
echo "$manageClients"


KAS=$(curl -sk --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/clients?clientId=admin-service-account)
kasClientId=$(jq -r '.[].id' <<< "$KAS")


SVC=$(curl -sk --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/clients/"$kasClientId"/service-account-user)
svcUserId=$(jq -r '.id' <<< "$SVC")
echo "$svcUserId"

FINAL=$(curl -sk --data-raw '[{"id": '"$manageUser"',"name": "manage-users"},{"id": '"$manageRealm"',"name": "manage-realm"},{"id": '"$manageClients"',"name": "manage-clients"}]' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/users/"$svcUserId"/role-mappings/clients/"$realmMgmtClientId")
echo "$FINAL"
