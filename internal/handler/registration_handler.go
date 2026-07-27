package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"cve-registration-api/internal/domain"
)

type Registrator interface {
	Register(ctx context.Context, form domain.RegistrationForm) (*domain.Registration, error)
	FindUserByCPF(ctx context.Context, cpf string) (*domain.UserPrivateStation, error)
}

type Searcher interface {
	Search(ctx context.Context, term string) ([]domain.Registration, error)
}

type RegistrationHandler struct {
	service Registrator
	repo    Searcher
}

func NewRegistrationHandler(service Registrator, repo Searcher) *RegistrationHandler {
	return &RegistrationHandler{service: service, repo: repo}
}

// Create: POST /registrations (protegido por AuthHandler.RequireAuth)
func (h *RegistrationHandler) Create(w http.ResponseWriter, r *http.Request) {
	var form domain.RegistrationForm
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	reg, err := h.service.Register(r.Context(), form)
	if err != nil {
		// Mesmo com erro, o registro já foi salvo (com status "error") —
		// devolvemos 422 com o motivo pra atuação manual no painel.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":           err.Error(),
			"registration_id": reg.ID,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "cadastrado com sucesso",
	})
}

// Search: GET /registrations?q=termo (protegido por AuthHandler.RequireAuth)
func (h *RegistrationHandler) Search(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	results, err := h.repo.Search(r.Context(), term)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro ao buscar cadastros")
		return
	}
	writeJSON(w, http.StatusOK, results)
}

// LookupByCPF: GET /users/by-cpf/{cpf}
// Proxy da CVE /api/v1/users_data/tenant_parent/cpf/{cpf} (com fallback).
func (h *RegistrationHandler) LookupByCPF(w http.ResponseWriter, r *http.Request) {
	cpf := strings.TrimSpace(r.PathValue("cpf"))
	if cpf == "" {
		writeError(w, http.StatusBadRequest, "CPF obrigatório")
		return
	}

	user, err := h.service.FindUserByCPF(r.Context(), cpf)
	if err != nil {
		msg := err.Error()
		status := http.StatusBadGateway
		if strings.Contains(msg, "não encontrado") || strings.Contains(msg, "inválido") {
			status = http.StatusNotFound
			if strings.Contains(msg, "inválido") {
				status = http.StatusBadRequest
			}
		}
		writeError(w, status, msg)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"error":              nil,
		"userPrivateStation": user,
	})
}
