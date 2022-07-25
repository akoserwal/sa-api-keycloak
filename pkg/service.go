package service

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
	"log"
	"net/http"
	"os"
	"regexp"
	"sa-api-keycloak/pkg/client"
	serviceaccountsclient "sa-api-keycloak/serviceaccountmgmt/apiv1/client"
	"strings"
	"time"
)

import (
	"context"
	"encoding/json"
	"errors"
)

const (
	jwksURL    = `http://127.0.0.1:8180/auth/realms/redhat-external/protocol/openid-connect/certs`
	created_at = "created_at"
	created_by = "created_by"
	rhOrgId    = "rh-org-id"
	rhUserId   = "rh-user-id"
	username   = "username"
)

type ServiceAccountService interface {
	GetServiceAccounts(w http.ResponseWriter, r *http.Request)
	GetServiceAccount(w http.ResponseWriter, r *http.Request)
	CreateServiceAccount(w http.ResponseWriter, r *http.Request)
	DeleteServiceAccount(w http.ResponseWriter, r *http.Request)
	ResetServiceAccountSecret(w http.ResponseWriter, r *http.Request)
}

type serviceAccountAPIServer struct {
	kcClient client.Client
}

func NewServiceAccountAPIServer(baseurl string) ServiceAccountService {
	kc := client.NewClient(baseurl, true)
	return &serviceAccountAPIServer{
		kcClient: kc,
	}
}

var _ ServiceAccountService = &serviceAccountAPIServer{}

func (kc serviceAccountAPIServer) GetServiceAccounts(w http.ResponseWriter, r *http.Request) {
	token, err := kc.kcClient.GetToken()
	if err != nil {
		errorResponse(w, err)
	}
	respclients, err := kc.kcClient.GetClients(token, 0, 100, "")

	var salist []serviceaccountsclient.ServiceAccountData

	for _, resp := range respclients {
		ValidUuidRegexp := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
		if ValidUuidRegexp.MatchString(*resp.ClientID) {
			respSa := serviceaccountsclient.ServiceAccountData{
				Id:          resp.ID,
				Name:        resp.Name,
				Description: resp.Description,
				ClientId:    resp.ClientID,
			}
			salist = append(salist, respSa)
		}

	}

	btArr, err := json.Marshal(salist)
	w.Header().Set("Content-Type", "application/json")
	w.Write(btArr)
	w.WriteHeader(http.StatusOK)
}

func (kc serviceAccountAPIServer) GetServiceAccount(w http.ResponseWriter, r *http.Request) {
	id := conStr(r.Context().Value("id"))
	token, err := kc.kcClient.GetToken()
	if err != nil {
		errorResponse(w, err)
	}
	resp, err := kc.kcClient.GetClientById(id, token)
	if err != nil { // abnormal response
		errorResponse(w, err)
		return
	}
	attributes := resp.Attributes
	att := *attributes
	createdAt, err := time.Parse(time.RFC3339, att["created_at"])
	t := createdAt.Unix()

	usr := att["username"]

	respSa := serviceaccountsclient.ServiceAccountData{
		Id:          resp.ID,
		Name:        resp.Name,
		Description: resp.Description,
		ClientId:    resp.ClientID,
		CreatedAt:   &t,
		CreatedBy:   &usr,
	}
	serviceAccountResponse(w, respSa, err)
}

func errorResponse(w http.ResponseWriter, err error) {
	sa := serviceaccountsclient.NewError(err.Error())
	er, _ := sa.MarshalJSON()
	sa.GetError()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(er)
}

func conStr(input any) string {
	var out string
	if input != nil {
		out = input.(string)
	}
	return out
}

func (kc serviceAccountAPIServer) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	var ssa serviceaccountsclient.ServiceAccountCreateRequestData
	err := json.NewDecoder(r.Body).Decode(&ssa)
	if err != nil {
		errorResponse(w, err)
		return
	}

	var rhOrgIdValue = conStr(r.Context().Value("rh-org-id"))
	var rhUserIdValue = conStr(r.Context().Value("rh-user-id"))
	var rhUsernameValue = conStr(r.Context().Value("username"))

	token, err := kc.kcClient.GetToken()
	if err != nil {
		errorResponse(w, err)
	}
	id, _ := uuid.NewUUID()
	t := time.Now()
	createdAt := t.Unix()
	//Format(time.RFC3339)

	rhOrgIdAttributes := map[string]string{
		rhOrgId:    rhOrgIdValue,
		rhUserId:   rhUserIdValue,
		username:   rhUsernameValue,
		created_by: rhUsernameValue,
		created_at: t.Format(time.RFC3339),
	}
	rhAccountID := map[string][]string{
		rhOrgId:    {rhOrgIdValue},
		rhUserId:   {rhUserIdValue},
		username:   {rhUsernameValue},
		created_by: {rhUsernameValue},
		created_at: {t.Format(time.RFC3339)},
	}
	OrgIdProtocolMapper := kc.kcClient.CreateProtocolMapperConfig(rhOrgId)
	userIdProtocolMapper := kc.kcClient.CreateProtocolMapperConfig(rhUserId)
	userProtocolMapper := kc.kcClient.CreateProtocolMapperConfig(username)
	protocolMapper := append(OrgIdProtocolMapper, userIdProtocolMapper...)
	protocolMapper = append(protocolMapper, userProtocolMapper...)

	c := client.ClientRepresentation{
		ID:                     id.String(),
		ClientID:               id.String(),
		Name:                   ssa.Name,
		Description:            *ssa.Description,
		ServiceAccountsEnabled: true,
		StandardFlowEnabled:    false,
		Attributes:             rhOrgIdAttributes,
		ProtocolMappers:        protocolMapper,
	}

	clientconfg := kc.kcClient.ClientConfig(c)
	internalClientId, err := kc.kcClient.CreateClient(clientconfg, token)
	if err != nil {
		errorResponse(w, err)
		return
	}
	resp, err := kc.kcClient.GetClient(internalClientId, token)
	if err != nil {
		errorResponse(w, err)
		return
	}

	serviceAccountUser, err := kc.kcClient.GetClientServiceAccount(token, internalClientId)
	if err != nil {
		errorResponse(w, err)
		return
	}
	serviceAccountUser.Attributes = &rhAccountID
	serAccUser := *serviceAccountUser

	err = kc.kcClient.UpdateServiceAccountUser(token, serAccUser)
	if err != nil {
		errorResponse(w, err)
		return
	}

	secret, err := kc.kcClient.GetClientSecret(internalClientId, token)
	if err != nil {
		errorResponse(w, err)
		return
	}
	createdby := rhUsernameValue
	respSa := serviceaccountsclient.ServiceAccountData{
		Id:          resp.ID,
		Name:        resp.Name,
		Description: resp.Description,
		ClientId:    resp.ClientID,
		Secret:      &secret,
		CreatedAt:   &createdAt,
		CreatedBy:   &createdby,
	}
	serviceAccountResponse(w, respSa, err)
}

func serviceAccountResponse(w http.ResponseWriter, respSa serviceaccountsclient.ServiceAccountData, err error) {
	bt, err := respSa.MarshalJSON()
	if err != nil {
		errorResponse(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bt)
	w.WriteHeader(http.StatusOK)
}

func (kc serviceAccountAPIServer) DeleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	id := conStr(r.Context().Value("id"))
	token, err := kc.kcClient.GetToken()
	if err != nil {
		errorResponse(w, err)
		return
	}
	err = kc.kcClient.DeleteClient(id, token)
	if err != nil {
		errorResponse(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (kc serviceAccountAPIServer) ResetServiceAccountSecret(w http.ResponseWriter, r *http.Request) {
	id := conStr(r.Context().Value("id"))
	token, err := kc.kcClient.GetToken()
	if err != nil {
		errorResponse(w, err)
		return
	}
	resp, err := kc.kcClient.RegenerateClientSecret(token, id)
	respSa := serviceaccountsclient.ServiceAccountData{
		Id:       &id,
		ClientId: &id,
		Secret:   resp.Value,
	}
	serviceAccountResponse(w, respSa, err)
}

var rootCmd = &cobra.Command{
	Use:   "service-account-api",
	Short: "service-account-api",
	Long:  `service-account-api`,
	Run:   Serve,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func Serve(cmd *cobra.Command, args []string) {
	router := mux.NewRouter()
	sa := NewServiceAccountAPIServer("http://127.0.0.1:8180")
	router.Use(AuthMiddleware)
	s := router.PathPrefix("/auth/realms/redhat-external/apis/service_accounts/v1").Subrouter()
	s.HandleFunc("", sa.CreateServiceAccount).Methods(http.MethodPost)
	s.HandleFunc("", sa.GetServiceAccounts).Methods(http.MethodGet)
	s.HandleFunc("/{id}", sa.GetServiceAccount).Methods(http.MethodGet)
	s.HandleFunc("/{id}", sa.DeleteServiceAccount).Methods(http.MethodDelete)
	s.HandleFunc("/{id}/resetSecret", sa.ResetServiceAccountSecret).Methods(http.MethodPost)
	srv := &http.Server{
		Handler:      router,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Println("service account service started at 127.0.0.1:8000")
	log.Fatal(srv.ListenAndServe())
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RequestURI)
		token, err := verifyToken(r)
		if token != nil {
			id := mux.Vars(r)["id"]
			orgid, _ := token.Get("rh-org-id")
			userid, _ := token.Get("rh-user-id")
			user, _ := token.Get("preferred_username")
			ctx := context.WithValue(context.Background(), "rh-org-id", orgid)
			ctx = context.WithValue(ctx, "rh-user-id", userid)
			ctx = context.WithValue(ctx, "username", user)
			ctx = context.WithValue(ctx, "id", id)
			next.ServeHTTP(w, r.WithContext(ctx))
		}

		if err != nil || token == nil {
			eer := serviceaccountsclient.NewError("Bearer token is required")
			bt, _ := eer.MarshalJSON()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(bt)

		}
	})
}

func verifyToken(request *http.Request) (jwt.Token, error) {
	strToken, err := GetAuthHeader(request)
	if err != nil {
		return nil, err
	}
	jwksKeySet, err := jwk.Fetch(request.Context(), jwksURL)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse([]byte(strToken), jwt.WithKeySet(jwksKeySet), jwt.WithValidate(true))
	if err != nil {
		return nil, err
	}
	return token, nil
}

func GetAuthHeader(request *http.Request) (string, error) {
	header := strings.Fields(request.Header.Get("Authorization"))
	if len(header) > 0 {
		if header[0] != "Bearer" {
			return "", errors.New("malformed token")
		}
		return header[1], nil
	}
	return "", errors.New("Bearer token is required")
}
