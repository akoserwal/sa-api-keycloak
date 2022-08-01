export KEYCLOAK_URL=http://localhost:8180
export KEYCLOAK_PORT_NO=8180
export KEYCLOAK_USER=admin
export KEYCLOAK_PASSWORD=admin
TOKEN_PATH="/auth/realms/redhat-external/protocol/openid-connect/token"

CLIENT_ID=admin-service-account
CLEINT_SECRET=admin-service-account


RESULT=$(curl -sk --data "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLEINT_SECRET" "$KEYCLOAK_URL"$TOKEN_PATH)
TOKEN=$(jq -r '.access_token' <<< "$RESULT")
echo "$TOKEN"