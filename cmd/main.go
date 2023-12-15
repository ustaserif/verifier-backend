package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	log "github.com/sirupsen/logrus"

	"github.com/0xPolygonID/verifier-backend/internal/api"
	"github.com/0xPolygonID/verifier-backend/internal/config"
	"github.com/0xPolygonID/verifier-backend/internal/errors"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.WithField("error", err).Error("cannot load config")
		return
	}

	keysLoader := &loaders.FSKeyLoader{Dir: cfg.KeyDIR}

	mux := chi.NewRouter()
	apiServer := api.New(keysLoader)
	api.HandlerFromMux(api.NewStrictHandlerWithOptions(apiServer, nil,
		api.StrictHTTPServerOptions{RequestErrorHandlerFunc: errors.RequestErrorHandlerFunc}), mux)
	api.RegisterStatic(mux)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.ApiPort),
		Handler: mux,
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.WithField("port", cfg.ApiPort).Info("server started")
		if err := server.ListenAndServe(); err != nil {
			log.WithField("error", err).Error("starting http server")
		}
	}()

	<-quit
	log.Info("Shutting down")
}
