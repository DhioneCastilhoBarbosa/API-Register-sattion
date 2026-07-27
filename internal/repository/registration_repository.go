package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"cve-registration-api/internal/domain"
)

type RegistrationRepository struct {
	db *sql.DB
}

func NewRegistrationRepository(db *sql.DB) *RegistrationRepository {
	return &RegistrationRepository{db: db}
}

func (r *RegistrationRepository) Create(ctx context.Context, reg *domain.Registration) error {
	formJSON, err := json.Marshal(reg.Form)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO charger_registrations (email, serial_number, status, form_data, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
		RETURNING id`

	return r.db.QueryRowContext(ctx, query,
		reg.Form.Email, reg.Form.SerialNumber, reg.Status, formJSON,
	).Scan(&reg.ID)
}

func (r *RegistrationRepository) UpdateResult(
	ctx context.Context,
	id int,
	status domain.RegistrationStatus,
	chargeBoxPk *int,
	licenseCode *string,
	errMsg *string,
) error {
	query := `
		UPDATE charger_registrations
		SET status = $2, cve_charge_box_pk = $3, license_code = $4, error_message = $5, updated_at = now()
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, status, chargeBoxPk, licenseCode, errMsg)
	return err
}

// Search cobre exatamente o que você pediu: buscar depois por nome, e-mail,
// número de série ou status de cadastro.
func (r *RegistrationRepository) Search(ctx context.Context, term string) ([]domain.Registration, error) {
	query := `
		SELECT id, form_data, status, cve_charge_box_pk, license_code, error_message, created_at, updated_at
		FROM charger_registrations
		WHERE email ILIKE '%' || $1 || '%'
		   OR serial_number ILIKE '%' || $1 || '%'
		   OR status ILIKE '%' || $1 || '%'
		   OR form_data->>'first_name' ILIKE '%' || $1 || '%'
		   OR form_data->>'last_name' ILIKE '%' || $1 || '%'
		ORDER BY created_at DESC
		LIMIT 100`

	rows, err := r.db.QueryContext(ctx, query, term)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []domain.Registration
	for rows.Next() {
		var reg domain.Registration
		var formJSON []byte
		if err := rows.Scan(
			&reg.ID, &formJSON, &reg.Status, &reg.CVEChargeBoxPk,
			&reg.LicenseCode, &reg.ErrorMessage, &reg.CreatedAt, &reg.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(formJSON, &reg.Form); err != nil {
			return nil, err
		}
		results = append(results, reg)
	}
	return results, rows.Err()
}
