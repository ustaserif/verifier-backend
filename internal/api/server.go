package api

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"

	"github.com/0xPolygonID/verifier-backend/internal/config"
	"github.com/0xPolygonID/verifier-backend/internal/loader"
)

// Server represents the API server
type Server struct {
	keyLoader *loaders.FSKeyLoader
	cfg       config.Config
	cache     *cache.Cache
}

// New creates a new API server
func New(cfg config.Config, keyLoader *loaders.FSKeyLoader) *Server {
	return &Server{
		cfg:       cfg,
		keyLoader: keyLoader,
		cache:     cache.New(60*time.Minute, 60*time.Minute),
	}
}

// RegisterStatic add method to the mux that are not documented in the API.
func RegisterStatic(mux *chi.Mux) {
	mux.Get("/", documentation)
	mux.Get("/static/docs/api/api.yaml", swagger)
	mux.Get("/favicon.ico", favicon)
}

// Health is a method
func (s *Server) Health(_ context.Context, _ HealthRequestObject) (HealthResponseObject, error) {
	var resp Health200JSONResponse = Health{"healthy": true}
	return resp, nil
}

// GetDocumentation this method will be overridden in the main function
func (s *Server) GetDocumentation(_ context.Context, _ GetDocumentationRequestObject) (GetDocumentationResponseObject, error) {
	return nil, nil
}

// Callback - handle callback endpoint
func (s *Server) Callback(ctx context.Context, request CallbackRequestObject) (CallbackResponseObject, error) {
	sessionID := request.Params.SessionID

	log.WithFields(log.Fields{
		"sessionID": sessionID,
		"token":     request.Body,
	}).Info("callback")

	authRequest, b := s.cache.Get(sessionID)
	if !b {
		log.WithFields(log.Fields{
			"sessionID": sessionID,
		}).Error("sessionID not found")
		return nil, fmt.Errorf("sessionID not found")
	}

	w3cLoader := loader.NewW3CDocumentLoader(nil, s.cfg.IPFSURL)

	resolvers := s.parseResolverSettings()
	verifier, err := auth.NewVerifier(s.keyLoader, resolvers, auth.WithDocumentLoader(w3cLoader))
	if err != nil {
		log.WithFields(log.Fields{
			"sessionID": sessionID,
			"err":       err,
		}).Error("failed to create verifier")
		return nil, err
	}

	_, err = verifier.FullVerify(ctx, *request.Body,
		authRequest.(protocol.AuthorizationRequestMessage),
		pubsignals.WithAcceptedStateTransitionDelay(time.Minute*5))
	if err != nil {
		log.WithFields(log.Fields{
			"sessionID": sessionID,
			"err":       err,
		}).Error("failed to verify")
		return nil, err
	}

	return Callback200JSONResponse{}, nil
}

// GetQRCodeFromStore - get QR code from store
func (s *Server) GetQRCodeFromStore(ctx context.Context, request GetQRCodeFromStoreRequestObject) (GetQRCodeFromStoreResponseObject, error) {
	return nil, nil
}

// QRStore - store QR code
func (s *Server) QRStore(ctx context.Context, request QRStoreRequestObject) (QRStoreResponseObject, error) {
	return nil, nil
}

// SignIn - sign in
func (s *Server) SignIn(ctx context.Context, request SignInRequestObject) (SignInResponseObject, error) {
	rURL := s.cfg.Host
	sessionID := rand.Intn(1000000)
	uri := fmt.Sprintf("%s%s?sessionID=%s", rURL, config.CallbackURL, strconv.Itoa(sessionID))

	var senderDID string
	if request.Body.Network == "mumbai" {
		senderDID = s.cfg.MumbaiSenderDID
	} else {
		senderDID = s.cfg.MainSenderDID
	}

	authorizationRequest := auth.CreateAuthorizationRequest("test flow", senderDID, uri)

	// TODO - Ask when could be false
	isLocal := true
	if isLocal {
		authorizationRequest.ID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
		authorizationRequest.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
	}

	//var customQuery models.CustomQuery
	mtpProofRequest := protocol.ZeroKnowledgeProofRequest{
		ID:        uint32(1),
		CircuitID: request.Body.CircuitID,
		Query:     request.Body.Query,
	}

	authorizationRequest.To = ""
	if request.Body.To != nil {
		authorizationRequest.To = *request.Body.To
	}

	authorizationRequest.Body.Scope = append(authorizationRequest.Body.Scope, mtpProofRequest)
	s.cache.Set(strconv.Itoa(sessionID), authorizationRequest, cache.DefaultExpiration)

	response := SignIn200JSONResponse{
		QrCode:    getQRCode(authorizationRequest),
		SessionID: sessionID,
	}

	return response, nil
}

func getQRCode(request protocol.AuthorizationRequestMessage) QRCode {
	scopes := make([]Scope, len(request.Body.Scope))
	for i, scope := range request.Body.Scope {
		scopes[i] = Scope{
			CircuitId: scope.CircuitID,
			Id:        int(scope.ID),
			Query:     scope.Query,
		}
	}

	var body = struct {
		CallbackUrl *string  `json:"callbackUrl,omitempty"`
		Reason      *string  `json:"reason,omitempty"`
		Scope       *[]Scope `json:"scope,omitempty"`
	}{
		CallbackUrl: &request.Body.CallbackURL,
		Reason:      &request.Body.Reason,
		Scope:       &scopes,
	}

	qrCode := QRCode{
		From: request.From,
		Id:   request.ID,
		Thid: request.ThreadID,
		Typ:  string(request.Typ),
		Type: string(request.Type),
		Body: body,
	}

	return qrCode
}

// Status - status
func (s *Server) Status(ctx context.Context, request StatusRequestObject) (StatusResponseObject, error) {
	return nil, nil
}

func documentation(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/spec.html", "text/html; charset=UTF-8", w)
}

func favicon(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/polygon.png", "image/png", w)
}

func swagger(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/api.yaml", "text/html; charset=UTF-8", w)
}

func writeFile(path string, mimeType string, w http.ResponseWriter) {
	f, err := os.ReadFile(path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
	w.Header().Set("Content-Type", mimeType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f)
}

// parseResolverSettings parses the resolver settings from the config file
func (s *Server) parseResolverSettings() map[string]pubsignals.StateResolver {
	resolvers := map[string]pubsignals.StateResolver{}
	for chainName, chainSettings := range s.cfg.ResolverSettings {
		for networkName, networkSettings := range chainSettings {
			prefix := fmt.Sprintf("%s:%s", chainName, networkName)
			resolver := state.NewETHResolver(networkSettings.NetworkURL, networkSettings.ContractAddress)
			resolvers[prefix] = resolver
		}
	}
	return resolvers
}
