package domain

// LicenseLoginRequest é o body do POST /login da API de Licenças
// (api-licenca.intelbras-cve-pro.com.br) — note que o campo de senha é
// "senha", diferente da API CVE-PRO que usa "password".
type LicenseLoginRequest struct {
	Email string `json:"email"`
	Senha string `json:"senha"`
}

// Chave espelha models.Chave — a "chave de acesso" vinculada a
// CPF/e-mail (rotas /buscar-chave, /chaves).
type Chave struct {
	Chave     string `json:"chave"`
	Conta     string `json:"conta"`
	CPF       string `json:"cpf"`
	Email     string `json:"email"`
	Nome      string `json:"nome"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// License espelha models.License — a licença de uso da plataforma
// (rota /licencas), vinculada a uma compra (codigo_compra).
type License struct {
	ID           int    `json:"id"`
	Codigo       string `json:"codigo"`
	CodigoCompra string `json:"codigo_compra"`
	Email        string `json:"email"`
	Nome         string `json:"nome"`
	Quantidade   int    `json:"quantidade"`
	Status       string `json:"status"`
	Validade     int    `json:"validade"`
	Coringa      bool   `json:"coringa"`
}
