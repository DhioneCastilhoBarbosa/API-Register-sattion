package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config concentra tudo que vem do .env. Nenhuma credencial fica no código —
// se faltar alguma variável obrigatória, Load() retorna erro e o serviço
// não deve subir.
type Config struct {
	Port string

	DatabaseURL string

	// API CVE-PRO
	CVEBaseURL       string
	CVEApiKey        string
	CVELoginEmail    string
	CVELoginPassword string
	CVETenantPk      int

	// API de Licenças
	LicenseBaseURL       string
	LicenseLoginEmail    string
	LicenseLoginPassword string

	// Autenticação da própria ferramenta (painel/formulário)
	JWTSecret string
}

func Load() (*Config, error) {
	// Carrega .env se existir; em produção as vars já vêm do ambiente.
	_ = godotenv.Load()

	cfg := &Config{
		Port:                 getEnv("PORT", "8080"),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		CVEBaseURL:           getEnv("CVE_BASE_URL", "https://cs-test.intelbras-cve-pro.com.br"),
		CVEApiKey:            os.Getenv("CVE_API_KEY"),
		CVELoginEmail:        os.Getenv("CVE_LOGIN_EMAIL"),
		CVELoginPassword:     os.Getenv("CVE_LOGIN_PASSWORD"),
		LicenseBaseURL:       getEnv("LICENSE_BASE_URL", "https://api-licenca.intelbras-cve-pro.com.br"),
		LicenseLoginEmail:    os.Getenv("LICENSE_LOGIN_EMAIL"),
		LicenseLoginPassword: os.Getenv("LICENSE_LOGIN_PASSWORD"),
		JWTSecret:            os.Getenv("JWT_SECRET"),
	}

	tenantPkStr := os.Getenv("CVE_TENANT_PK")
	tenantPk, err := strconv.Atoi(tenantPkStr)
	if err != nil {
		return nil, fmt.Errorf("CVE_TENANT_PK inválido ou não definido (%q): %w", tenantPkStr, err)
	}
	cfg.CVETenantPk = tenantPk

	missing := map[string]string{
		"DATABASE_URL":           cfg.DatabaseURL,
		"CVE_API_KEY":            cfg.CVEApiKey,
		"CVE_LOGIN_EMAIL":        cfg.CVELoginEmail,
		"CVE_LOGIN_PASSWORD":     cfg.CVELoginPassword,
		"LICENSE_LOGIN_EMAIL":    cfg.LicenseLoginEmail,
		"LICENSE_LOGIN_PASSWORD": cfg.LicenseLoginPassword,
		"JWT_SECRET":             cfg.JWTSecret,
	}
	for name, value := range missing {
		if value == "" {
			return nil, fmt.Errorf("variável de ambiente obrigatória não definida: %s", name)
		}
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
