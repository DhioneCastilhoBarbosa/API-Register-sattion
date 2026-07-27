package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	"cve-registration-api/internal/auth"
	"cve-registration-api/internal/config"
	"cve-registration-api/internal/cveclient"
	"cve-registration-api/internal/handler"
	"cve-registration-api/internal/licenseclient"
	"cve-registration-api/internal/migrate"
	"cve-registration-api/internal/repository"
	"cve-registration-api/internal/service"
	"cve-registration-api/migrations"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuração inválida: %v", err)
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("erro ao abrir conexão com o Postgres: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("erro ao conectar no Postgres: %v", err)
	}

	if err := migrate.Up(db, migrations.FS); err != nil {
		log.Fatalf("erro ao aplicar migrations: %v", err)
	}

	// Clients externos
	cveClient := cveclient.New(cfg.CVEBaseURL, cfg.CVEApiKey, cfg.CVELoginEmail, cfg.CVELoginPassword, cfg.CVETenantPk)
	licenseClient := licenseclient.New(cfg.LicenseBaseURL, cfg.LicenseLoginEmail, cfg.LicenseLoginPassword)

	// Repositórios
	registrationRepo := repository.NewRegistrationRepository(db)
	panelUserRepo := repository.NewPanelUserRepository(db)

	// Serviço de orquestração
	registrationService := service.NewRegistrationService(cveClient, licenseClient, registrationRepo, cfg.CVETenantPk)

	// Autenticação do painel/formulário
	tokenManager := auth.NewManager(cfg.JWTSecret)
	authHandler := handler.NewAuthHandler(panelUserRepo, tokenManager)
	registrationHandler := handler.NewRegistrationHandler(registrationService, registrationRepo)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", authHandler.Register)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("GET /users/by-cpf/{cpf}", authHandler.RequireAuth(registrationHandler.LookupByCPF))
	mux.HandleFunc("POST /registrations", authHandler.RequireAuth(registrationHandler.Create))
	mux.HandleFunc("GET /registrations", authHandler.RequireAuth(registrationHandler.Search))

	log.Printf("subindo na porta %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("erro ao subir servidor: %v", err)
	}
}
