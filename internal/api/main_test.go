package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/iden3/go-iden3-auth/v2/loaders"

	"github.com/0xPolygonID/verifier-backend/internal/config"
	"github.com/0xPolygonID/verifier-backend/internal/errors"
)

var (
	cfg        config.Config
	keysLoader *loaders.FSKeyLoader
)

func TestMain(m *testing.M) {

	cfg = config.Config{
		Host:            "http://localhost",
		ApiPort:         "3000",
		KeyDIR:          "./keys",
		MumbaiSenderDID: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
		MainSenderDID:   "did:polygonid:polygon:main:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
		IPFSURL:         "https://gateway.pinata.cloud",
		ResolverSettings: config.ResolverSettings{
			"polygon": {
				"mumbai": {
					ContractAddress: "0x2C1DdDc4C8b6BdAaE831eF04bF4FfDfA575d8bA7",
					NetworkURL:      "https://rpc-mumbai.maticvigil.com",
				},
			},
		},
	}

	keysLoader = &loaders.FSKeyLoader{Dir: cfg.KeyDIR}
	m.Run()
}

func getHandler(ctx context.Context, server *Server) http.Handler {
	mux := chi.NewRouter()
	RegisterStatic(mux)
	return HandlerFromMux(NewStrictHandlerWithOptions(
		server,
		nil,
		StrictHTTPServerOptions{
			RequestErrorHandlerFunc: errors.RequestErrorHandlerFunc,
		},
	), mux)
}
