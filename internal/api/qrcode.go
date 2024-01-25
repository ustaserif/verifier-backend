package api

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type qrCache interface {
	Get(id string) (any, bool)
	Set(id string, data any, duration time.Duration)
}

type QRcodeStore struct {
	cache qrCache
}

func NewQRCodeStore(c qrCache) *QRcodeStore {
	return &QRcodeStore{cache: c}
}

func (s *QRcodeStore) Get(id uuid.UUID) (*QRCode, error) {
	data, ok := s.cache.Get(s.key() + id.String())
	if !ok {
		return nil, errors.New("sessionID not found")
	}

	qr, ok := data.(QRCode)
	if !ok {
		return nil, errors.New("failed to cast data to QRCode")
	}
	return &qr, nil
}

func (s *QRcodeStore) Save(host string, qrCode QRCode) (string, error) {
	uv := uuid.New()
	s.cache.Set(s.key()+uv.String(), qrCode, 1*time.Hour)
	return fmt.Sprintf("iden3comm://?request_uri=%s%s?id=%s", host, "/qr-store", uv.String()), nil
}

func (s *QRcodeStore) key() string {
	return "qr-code-"
}
