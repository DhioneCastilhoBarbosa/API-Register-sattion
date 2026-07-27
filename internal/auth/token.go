package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidToken = errors.New("token inválido ou expirado")

type Claims struct {
	Subject   string    `json:"sub"`
	ExpiresAt time.Time `json:"exp"`
}

// Manager emite e valida tokens simples (payload.assinatura, HMAC-SHA256)
// pra autenticar quem usa o painel/formulário — independente dos logins da
// API CVE-PRO e da API de Licenças, que são geridos à parte pelos seus
// próprios clients.
type Manager struct {
	secret []byte
}

func NewManager(secret string) *Manager {
	return &Manager{secret: []byte(secret)}
}

func (m *Manager) Issue(subject string, ttl time.Duration) (string, error) {
	claims := Claims{Subject: subject, ExpiresAt: time.Now().Add(ttl)}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := m.sign(encodedPayload)
	return fmt.Sprintf("%s.%s", encodedPayload, signature), nil
}

func (m *Manager) Validate(token string) (*Claims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}
	encodedPayload, signature := parts[0], parts[1]

	if !hmac.Equal([]byte(m.sign(encodedPayload)), []byte(signature)) {
		return nil, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if time.Now().After(claims.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

func (m *Manager) sign(data string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
