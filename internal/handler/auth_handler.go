package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"cve-registration-api/internal/auth"
)

type contextKey string

const userContextKey contextKey = "user"

// UserStore autentica quem acessa o painel/formulário (o time que faz os
// cadastros) — implementado contra a tabela panel_users no Postgres.
type UserStore interface {
	Create(ctx context.Context, email, password string) (userID string, err error)
	VerifyPassword(ctx context.Context, email, password string) (userID string, ok bool, err error)
}

type AuthHandler struct {
	users  UserStore
	tokens *auth.Manager
}

func NewAuthHandler(users UserStore, tokens *auth.Manager) *AuthHandler {
	return &AuthHandler{users: users, tokens: tokens}
}

// Register: POST /auth/register — cria usuário com enabled=false.
// O acesso só funciona depois de liberar no banco:
//
//	UPDATE panel_users SET enabled = true WHERE email = '...';
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	email := strings.TrimSpace(req.Email)
	if email == "" || !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "e-mail inválido")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "senha deve ter no mínimo 8 caracteres")
		return
	}

	userID, err := h.users.Create(r.Context(), email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrEmailTaken) {
			writeError(w, http.StatusConflict, "e-mail já cadastrado")
			return
		}
		writeError(w, http.StatusInternalServerError, "erro ao cadastrar usuário")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":      userID,
		"email":   strings.ToLower(email),
		"message": "usuário criado; aguarde liberação de acesso",
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	userID, ok, err := h.users.VerifyPassword(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrUserDisabled) {
			writeError(w, http.StatusForbidden, "usuário aguardando liberação de acesso")
			return
		}
		writeError(w, http.StatusInternalServerError, "erro ao verificar credenciais")
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "e-mail ou senha inválidos")
		return
	}

	token, err := h.tokens.Issue(userID, 8*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro ao gerar token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// RequireAuth protege as rotas do painel — exige "Authorization: Bearer <token>".
func (h *AuthHandler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authz, "Bearer ")
		if token == "" || token == authz {
			writeError(w, http.StatusUnauthorized, "token ausente")
			return
		}

		claims, err := h.tokens.Validate(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "token inválido ou expirado")
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
