package api

import (
	"context"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/iden3/go-iden3-auth/v2/loaders"
)

// Server represents the API server
type Server struct {
	keyLoader *loaders.FSKeyLoader
}

// New creates a new API server
func New(keyLoader *loaders.FSKeyLoader) *Server {
	return &Server{
		keyLoader: keyLoader,
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
	return nil, nil
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
	return nil, nil
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
