# Service Account API

Replica of SSO Service Account API


# Setup Local Keycloak instance
`make sso/setup`

## Setup configuration
`make sso/config`


# Build Binary
`make binary`

# Run SSO Service Account Service
`./service-account-api`


# Create User in SSO & update 
`./token.sh`

# Create service account
curl -v POST -H "Content-Type: application/json" -H "Authorization: Bearer $(TOKEN)" http://127.0.0.1:8000/auth/realms/redhat-external/apis/service_accounts/v1 -d '{"name":"test", "description":"test"}'


