package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Nerzal/gocloak/v11"
	"github.com/pkg/errors"
)

var (
	protocol = "openid-connect"
	mapper   = "oidc-usermodel-attribute-mapper"
)

type Client interface {
	GetToken() (string, error)
	CreateClient(client gocloak.Client, accessToken string) (string, error)
	ClientConfig(client ClientRepresentation) gocloak.Client
	GetClient(clientId string, accessToken string) (*gocloak.Client, error)
	DeleteClient(internalClientID string, accessToken string) error
	RegenerateClientSecret(accessToken string, id string) (*gocloak.CredentialRepresentation, error)
	GetClientById(id string, accessToken string) (*gocloak.Client, error)
	GetClientSecret(internalClientId string, accessToken string) (string, error)
	UpdateServiceAccountUser(accessToken string, serviceAccountUser gocloak.User) error
	GetClients(accessToken string, first int, max int, attribute string) ([]*gocloak.Client, error)
	GetClientServiceAccount(accessToken string, internalClient string) (*gocloak.User, error)
	CreateProtocolMapperConfig(name string) []gocloak.ProtocolMapperRepresentation
}

type kcClient struct {
	kcClient     gocloak.GoCloak
	ctx          context.Context
	realm        string
	clientId     string
	clientSecret string
}

func (kc kcClient) GetToken() (string, error) {
	clientCredentials := "client_credentials"
	options := gocloak.TokenOptions{
		ClientID:     &kc.clientId,
		GrantType:    &clientCredentials,
		ClientSecret: &kc.clientSecret,
	}
	tokenResp, err := kc.kcClient.GetToken(kc.ctx, kc.realm, options)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve the token: +%v", err.Error())
	}
	return tokenResp.AccessToken, nil
}

func newClient(baseUrl string, debug bool) gocloak.GoCloak {
	client := gocloak.NewClient(baseUrl)
	client.RestyClient().SetDebug(debug)
	client.RestyClient().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: false})
	return client
}

func NewClient(baseUrl string, realm string, debug bool, clientId string, clientSecret string) *kcClient {
	client := gocloak.NewClient(baseUrl)
	client.RestyClient().SetDebug(debug)
	client.RestyClient().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	return &kcClient{
		kcClient:     client,
		ctx:          context.Background(),
		realm:        realm,
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

var _ Client = &kcClient{}

type ClientRepresentation struct {
	ID                           string
	Name                         string
	ClientID                     string
	ServiceAccountsEnabled       bool
	Secret                       *string
	StandardFlowEnabled          bool
	Attributes                   map[string]string
	AuthorizationServicesEnabled bool
	ProtocolMappers              []gocloak.ProtocolMapperRepresentation
	Description                  string
	RedirectURIs                 *[]string
}

func (kc *kcClient) ClientConfig(client ClientRepresentation) gocloak.Client {
	publicClient := false
	directAccess := false
	return gocloak.Client{
		ID:                           &client.ID,
		Name:                         &client.Name,
		ClientID:                     &client.ClientID,
		ServiceAccountsEnabled:       &client.ServiceAccountsEnabled,
		StandardFlowEnabled:          &client.StandardFlowEnabled,
		Attributes:                   &client.Attributes,
		AuthorizationServicesEnabled: &client.AuthorizationServicesEnabled,
		ProtocolMappers:              &client.ProtocolMappers,
		Description:                  &client.Description,
		RedirectURIs:                 client.RedirectURIs,
		Protocol:                     &protocol,
		PublicClient:                 &publicClient,
		DirectAccessGrantsEnabled:    &directAccess,
	}
}

func (kc *kcClient) CreateProtocolMapperConfig(name string) []gocloak.ProtocolMapperRepresentation {
	protocolMapper := []gocloak.ProtocolMapperRepresentation{
		{
			Name:           &name,
			Protocol:       &protocol,
			ProtocolMapper: &mapper,
			Config: &map[string]string{
				"access.token.claim":   "true",
				"claim.name":           name,
				"id.token.claim":       "true",
				"jsonType.label":       "String",
				"user.attribute":       name,
				"userinfo.token.claim": "true",
			},
		},
	}
	return protocolMapper
}

func (kc *kcClient) CreateClient(client gocloak.Client, accessToken string) (string, error) {
	internalClientID, err := kc.kcClient.CreateClient(kc.ctx, accessToken, kc.realm, client)
	if err != nil {
		return "", err
	}
	return internalClientID, err
}

func (kc *kcClient) GetClient(clientId string, accessToken string) (*gocloak.Client, error) {
	params := gocloak.GetClientsParams{
		ClientID: &clientId,
	}
	clients, err := kc.kcClient.GetClients(kc.ctx, accessToken, kc.realm, params)
	if err != nil {
		return nil, err
	}
	for _, client := range clients {
		if *client.ClientID == clientId {
			return client, nil
		}
	}
	return nil, nil
}

func (kc *kcClient) DeleteClient(internalClientID string, accessToken string) error {
	return kc.kcClient.DeleteClient(kc.ctx, accessToken, kc.realm, internalClientID)
}

func (kc *kcClient) RegenerateClientSecret(accessToken string, id string) (*gocloak.CredentialRepresentation, error) {
	credRep, err := kc.kcClient.RegenerateClientSecret(kc.ctx, accessToken, kc.realm, id)
	if err != nil {
		return nil, err
	}
	return credRep, err
}

func (kc *kcClient) GetClientById(internalId string, accessToken string) (*gocloak.Client, error) {
	client, err := kc.kcClient.GetClient(kc.ctx, accessToken, kc.realm, internalId)
	if err != nil {
		return nil, err
	}
	return client, err
}
func (kc *kcClient) GetClientSecret(internalClientId string, accessToken string) (string, error) {
	resp, err := kc.kcClient.GetClientSecret(kc.ctx, accessToken, kc.realm, internalClientId)
	if err != nil {
		return "", err
	}
	if resp.Value == nil {
		return "", errors.Errorf("failed to retrieve credentials")
	}
	return *resp.Value, err
}
func (kc *kcClient) GetClients(accessToken string, first int, max int, attribute string) ([]*gocloak.Client, error) {
	params := gocloak.GetClientsParams{
		First:                &first,
		SearchableAttributes: &attribute,
	}

	clients, err := kc.kcClient.GetClients(kc.ctx, accessToken, kc.realm, params)
	if err != nil {
		return nil, err
	}
	return clients, err
}

func (kc *kcClient) UpdateServiceAccountUser(accessToken string, serviceAccountUser gocloak.User) error {
	err := kc.kcClient.UpdateUser(kc.ctx, accessToken, kc.realm, serviceAccountUser)
	if err != nil {
		return err
	}
	return err
}

func (kc *kcClient) GetClientServiceAccount(accessToken string, internalClient string) (*gocloak.User, error) {
	serviceAccountUser, err := kc.kcClient.GetClientServiceAccount(kc.ctx, accessToken, kc.realm, internalClient)
	if err != nil {
		return nil, err

	}
	return serviceAccountUser, err
}
