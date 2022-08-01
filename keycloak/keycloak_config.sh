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


CREATESCOPE=$(curl -sk --data-raw '{
  "name": "rhscope",
  "description": "",
  "attributes": {
    "consent.screen.text": "",
    "display.on.consent.screen": "true",
    "include.in.token.scope": "true",
    "gui.order": ""
  },
  "type": "default",
  "protocol": "openid-connect"
}' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/client-scopes)
echo $CREATESCOPE
#http://127.0.0.1:8180/auth/admin/realms/redhat-external/client-scopes/2bca4e13-9d43-4b33-a665-acdc94497f71/protocol-mappers/models

# http://127.0.0.1:8180/auth/admin/realms/redhat-external/client-scopes

#jq -c '.[] | select( .name | contains("rhscope")).id'

CS=$(curl -sk --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/client-scopes)
csId=$(jq -c '.[] | select( .name | contains("rhscope")).id' <<< "$CS")
scopeid=$(echo $csId | tr -d '"')
echo $scopeid
echo "clientscope: $csId"

echo "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/client-scopes/$scopeid/protocol-mappers/models

CREATEMAP=$(curl -sk --data-raw '{ "protocol": "openid-connect","protocolMapper": "oidc-usermodel-attribute-mapper",
                                      "name": "rh-org-id",
                                      "config": {
                                        "user.attribute": "rh-org-id",
                                        "claim.name": "rh-org-id",
                                        "jsonType.label": "",
                                        "id.token.claim": "true",
                                        "access.token.claim": "true",
                                        "userinfo.token.claim": "true",
                                        "multivalued": false,
                                        "aggregate.attrs": false
                                      }
                                    }' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/client-scopes/"$scopeid"/protocol-mappers/models)
echo $CREATEMAP

CREATEMAPtwo=$(curl -sk --data-raw '{ "protocol": "openid-connect","protocolMapper": "oidc-usermodel-attribute-mapper",
                                      "name": "rh-user-id",
                                      "config": {
                                        "user.attribute": "rh-user-id",
                                        "claim.name": "rh-user-id",
                                        "jsonType.label": "",
                                        "id.token.claim": "true",
                                        "access.token.claim": "true",
                                        "userinfo.token.claim": "true",
                                        "multivalued": false,
                                        "aggregate.attrs": false
                                      }
                                    }' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/client-scopes/"$scopeid"/protocol-mappers/models)
echo $CREATEMAPtwo

#http://127.0.0.1:8180/auth/admin/realms/redhat-external/users


CREATEuser=$(curl -sk --data-raw '{
                                      "username": "test",
                                      "email": "test@test.com",
                                      "firstName": "",
                                      "lastName": "",
                                      "emailVerified": false,
                                      "enabled": true,
                                      "attributes": {
                                          "rh-org-id": [
                                            "3333"
                                          ],
                                          "rh-user-id": [
                                            "3333"
                                          ]
                                        },
                                      "requiredActions": [],
                                      "groups": []
                                    }' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/users)
echo $CREATEuser



USERS=$(curl -sk --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/users?briefRepresentation=true&first=0&max=11)
userid=$(jq -c '.[] | select( .username | contains("test")).id' <<< "$USERS")

echo $userid

#http://127.0.0.1:8180/auth/admin/realms/redhat-external/users/78310bbf-afc6-4955-aadc-1074ee59c5da/reset-password

suserid=$(echo $userid | tr -d '"')
CREATEuserpass=$(curl -X PUT --data-raw '{
                                        "temporary": false,
                                        "type": "password",
                                        "value": "test"
                                      }' --header "Content-Type: application/json" --header "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL"/auth/admin/realms/redhat-external/users/"$suserid"/reset-password)
echo $CREATEuserpass


echo "completed"

#http://127.0.0.1:8180/auth/admin/realms/redhat-external/users?briefRepresentation=true&first=0&max=11

