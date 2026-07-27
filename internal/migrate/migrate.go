package migrate

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"
)

// Up aplica migrations pendentes em ordem de nome de arquivo.
// Cada arquivo é registrado em schema_migrations para não rodar de novo.
func Up(db *sql.DB, migrationFS fs.FS) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("criar schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return fmt.Errorf("listar migrations: %w", err)
	}

	var files []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".sql") {
			files = append(files, name)
		}
	}
	sort.Strings(files)

	for _, name := range files {
		var exists bool
		if err := db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE filename = $1)`, name,
		).Scan(&exists); err != nil {
			return fmt.Errorf("checar migration %s: %w", name, err)
		}
		if exists {
			continue
		}

		content, err := fs.ReadFile(migrationFS, name)
		if err != nil {
			return fmt.Errorf("ler migration %s: %w", name, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("executar migration %s: %w", name, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (filename) VALUES ($1)`, name,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("registrar migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}

		log.Printf("migration aplicada: %s", name)
	}

	return nil
}
