package repository

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"cve-registration-api/internal/auth"
)

// PanelUserRepository implementa handler.UserStore contra a tabela panel_users.
type PanelUserRepository struct {
	db *sql.DB
}

func NewPanelUserRepository(db *sql.DB) *PanelUserRepository {
	return &PanelUserRepository{db: db}
}

func (r *PanelUserRepository) Create(ctx context.Context, email, password string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	var id int
	err = r.db.QueryRowContext(ctx,
		`INSERT INTO panel_users (email, password_hash, enabled)
		 VALUES ($1, $2, false)
		 RETURNING id`,
		email, string(hash),
	).Scan(&id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return "", auth.ErrEmailTaken
		}
		return "", err
	}

	return strconv.Itoa(id), nil
}

func (r *PanelUserRepository) VerifyPassword(ctx context.Context, email, password string) (string, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	var id int
	var passwordHash string
	var enabled bool

	err := r.db.QueryRowContext(ctx,
		`SELECT id, password_hash, enabled FROM panel_users WHERE email = $1`, email,
	).Scan(&id, &passwordHash, &enabled)

	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
		return "", false, nil
	}
	if !enabled {
		return "", false, auth.ErrUserDisabled
	}

	return strconv.Itoa(id), true, nil
}
