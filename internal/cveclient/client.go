package cveclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cve-registration-api/internal/domain"
)

// Client fala com a API CVE-PRO (cs-test.intelbras-cve-pro.com.br). Login é
// automático: a primeira chamada dispara o login, e qualquer 401 força um
// novo login e repete a chamada uma vez.
type Client struct {
	baseURL    string
	apiKey     string
	email      string
	password   string
	tenantPk   int
	httpClient *http.Client

	mu    sync.Mutex
	token string
}

func New(baseURL, apiKey, email, password string, tenantPk int) *Client {
	return &Client{
		baseURL:  baseURL,
		apiKey:   apiKey,
		email:    email,
		password: password,
		tenantPk: tenantPk,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *Client) TenantPk() int { return c.tenantPk }

func (c *Client) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login(ctx)
}

func (c *Client) login(ctx context.Context) error {
	body, _ := json.Marshal(domain.CVELoginRequest{
		Email:    c.email,
		Password: c.password,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Api-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login na API CVE-PRO: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login na API CVE-PRO falhou (status %d): %s", resp.StatusCode, string(respBody))
	}

	var loginResp domain.CVELoginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return fmt.Errorf("parse da resposta de login: %w", err)
	}
	if loginResp.Token == "" {
		return fmt.Errorf("resposta de login sem token: %s", string(respBody))
	}

	c.token = loginResp.Token
	return nil
}

// do executa a requisição já com Authorization, relogando uma vez em caso
// de 401. Não envia Platform: DASHBOARD — com a conta de API isso retorna 401
// em /users_data e /chargepoints.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()

	if token == "" {
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
		c.mu.Lock()
		token = c.token
		c.mu.Unlock()
	}

	doRequest := func(tok string) (*http.Response, error) {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", tok)
		return c.httpClient.Do(req)
	}

	resp, err := doRequest(token)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
		c.mu.Lock()
		token = c.token
		c.mu.Unlock()
		return doRequest(token)
	}

	return resp, nil
}

// CreateChargepoint faz POST /api/v1/chargepoints. A rota só devolve
// {error} — sem o chargeBoxPk criado — então use FindChargeBoxPk depois
// pra descobrir o pk.
func (c *Client) CreateChargepoint(ctx context.Context, form domain.ChargePointRestForm) error {
	form.TenantPk = c.tenantPk

	body, err := json.Marshal(form)
	if err != nil {
		return err
	}

	resp, err := c.do(ctx, http.MethodPost, "/api/v1/chargepoints", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	// A CVE-PRO responde 202 Accepted (body vazio) quando o create persiste.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("%s", chargepointCreateError(form.ChargeBoxID, resp.StatusCode, respBody))
	}

	if len(respBody) > 0 {
		var errResp domain.ErrorRestResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("%s", chargepointCreateError(form.ChargeBoxID, resp.StatusCode, respBody))
		}
	}

	return nil
}

func chargepointCreateError(chargeBoxID string, status int, body []byte) string {
	var errResp domain.ErrorRestResponse
	_ = json.Unmarshal(body, &errResp)
	msg := strings.ToLower(errResp.Error)
	raw := strings.ToLower(string(body))

	switch {
	case strings.Contains(msg, "failed to update"),
		strings.Contains(msg, "failed to add"),
		strings.Contains(msg, "already exists"),
		strings.Contains(msg, "já existe"):
		return fmt.Sprintf("carregador com número de série %q já está cadastrado", chargeBoxID)
	case status == http.StatusServiceUnavailable || strings.Contains(raw, "503") || strings.Contains(raw, "<html"):
		return "cadastro do chargepoint falhou: API CVE-PRO indisponível (503). Verifique CVE_BASE_URL no ambiente e se o servidor de produção consegue acessar a CVE"
	case errResp.Error != "":
		return fmt.Sprintf("cadastro do chargepoint falhou: %s", errResp.Error)
	default:
		return fmt.Sprintf("cadastro do chargepoint falhou (status %d): %s", status, truncateForError(string(body), 200))
	}
}

func truncateForError(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// FindChargeBoxPkByFilter busca o chargeBoxPk só pelo filtro chargeBoxId=,
// sem varrer a listagem ampla (rápido; usado após create sem bloquear resposta).
func (c *Client) FindChargeBoxPkByFilter(ctx context.Context, chargeBoxID string) (int, error) {
	path := "/api/v1/chargepoints?" + url.Values{"chargeBoxId": {chargeBoxID}}.Encode()

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("busca do chargepoint falhou (status %d): %s", resp.StatusCode, string(b))
	}

	var listResp domain.ChargePointListRestResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return 0, err
	}
	for _, item := range listResp.ChargePointList {
		if item.ChargeBoxID == chargeBoxID {
			return item.ChargeBoxPk, nil
		}
	}

	return 0, fmt.Errorf("nenhum chargepoint encontrado com chargeBoxId %q", chargeBoxID)
}

// FindChargeBoxPk busca o chargeBoxPk pelo chargeBoxId (número de série).
// Tenta o filtro chargeBoxId= e, se vazio, varre a listagem (algumas
// respostas da CVE ignoram o filtro).
func (c *Client) FindChargeBoxPk(ctx context.Context, chargeBoxID string) (int, error) {
	path := "/api/v1/chargepoints?" + url.Values{"chargeBoxId": {chargeBoxID}}.Encode()

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("busca do chargepoint falhou (status %d): %s", resp.StatusCode, string(b))
	}

	var listResp domain.ChargePointListRestResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return 0, err
	}
	for _, item := range listResp.ChargePointList {
		if item.ChargeBoxID == chargeBoxID {
			return item.ChargeBoxPk, nil
		}
	}

	// Fallback: listagem ampla com match exato.
	if pk, err := c.scanChargeBoxPk(ctx, chargeBoxID); err == nil {
		return pk, nil
	}

	return 0, fmt.Errorf("nenhum chargepoint encontrado com chargeBoxId %q", chargeBoxID)
}

func (c *Client) scanChargeBoxPk(ctx context.Context, chargeBoxID string) (int, error) {
	path := "/api/v1/chargepoints?" + url.Values{"limit": {"200"}}.Encode()
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("listagem de chargepoints falhou (status %d)", resp.StatusCode)
	}
	var listResp domain.ChargePointListRestResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return 0, err
	}
	for _, item := range listResp.ChargePointList {
		if item.ChargeBoxID == chargeBoxID {
			return item.ChargeBoxPk, nil
		}
	}
	return 0, fmt.Errorf("não encontrado na listagem")
}

// UserExists checa via POST /api/v1/users/exist_email se já existe conta
// com esse e-mail no app CVE (rota usa Api-Key, não Authorization).
func (c *Client) UserExists(ctx context.Context, email string) (bool, error) {
	body, _ := json.Marshal(domain.UserVerify{Email: email})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/users/exist_email", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Api-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("exist_email falhou (status %d): %s", resp.StatusCode, string(b))
	}

	var existResp domain.ExistResponse
	if err := json.NewDecoder(resp.Body).Decode(&existResp); err != nil {
		return false, err
	}
	return existResp.Value, nil
}

// FindUserPkByEmail busca o user_pk via GET /api/v1/users_data?email=...
func (c *Client) FindUserPkByEmail(ctx context.Context, email string) (int, error) {
	path := "/api/v1/users_data?" + url.Values{"email": {email}}.Encode()

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("busca de usuário falhou (status %d): %s", resp.StatusCode, string(b))
	}

	var listResp domain.UserListRestResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return 0, err
	}
	if len(listResp.UserList) == 0 {
		return 0, fmt.Errorf("nenhum usuário encontrado com e-mail %q", email)
	}

	return listResp.UserList[0].UserPk, nil
}

// FindUserByCPF consulta GET /api/v1/users_data/tenant_parent/cpf/{cpf}.
// Se a rota da CVE falhar, faz fallback em users_data?docNumber= filtrando
// o CPF exato (a conta de API às vezes toma 500 em tenant_parent).
func (c *Client) FindUserByCPF(ctx context.Context, cpf string) (*domain.UserPrivateStation, error) {
	cpf = digitsOnly(cpf)
	if len(cpf) < 11 {
		return nil, fmt.Errorf("CPF inválido")
	}

	path := "/api/v1/users_data/tenant_parent/cpf/" + url.PathEscape(cpf)
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		var payload domain.UserPrivateStationResponse
		if err := json.Unmarshal(respBody, &payload); err != nil {
			return nil, fmt.Errorf("parse da resposta por CPF: %w", err)
		}
		if payload.Error != nil && *payload.Error != "" {
			return nil, fmt.Errorf("busca por CPF: %s", *payload.Error)
		}
		if payload.UserPrivateStation != nil && payload.UserPrivateStation.UserPk != 0 {
			return payload.UserPrivateStation, nil
		}
	}

	// Fallback: listagem por docNumber.
	return c.findUserByDocNumber(ctx, cpf)
}

func (c *Client) findUserByDocNumber(ctx context.Context, cpf string) (*domain.UserPrivateStation, error) {
	path := "/api/v1/users_data?" + url.Values{"docNumber": {cpf}}.Encode()
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("busca por CPF falhou (status %d): %s", resp.StatusCode, string(b))
	}

	var listResp domain.UserListRestResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}

	var match *domain.UserOverview
	for i := range listResp.UserList {
		u := &listResp.UserList[i]
		if digitsOnly(u.DocNumber) != cpf {
			continue
		}
		match = u
		// Prefere usuário do tenant Intelbras quando houver vários com o mesmo CPF.
		if strings.EqualFold(u.Tenant, "Intelbras") {
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("nenhum usuário encontrado com CPF %s", cpf)
	}

	return &domain.UserPrivateStation{
		Email:         match.Email,
		Phone:         match.Phone,
		UserPk:        match.UserPk,
		UserName:      match.Name,
		DocType:       match.DocType,
		DocNumber:     match.DocNumber,
		OcppIDTag:     match.OcppIdTag,
		BindExists:    false,
		TenantName:    match.Tenant,
		TenantRelated: false,
	}, nil
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CreateOcppTag faz POST /api/v1/ocpptags para cadastrar uma TagRFID.
// Se a idTag já existir, considera sucesso (idempotente — útil em retentativas).
func (c *Client) CreateOcppTag(ctx context.Context, form domain.OcppTagForm) error {
	form.TenantPk = c.tenantPk

	body, err := json.Marshal(form)
	if err != nil {
		return err
	}

	resp, err := c.do(ctx, http.MethodPost, "/api/v1/ocpptags", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		if isOcppTagAlreadyExists(respBody) {
			return nil
		}
		return fmt.Errorf("cadastro da tag RFID falhou (status %d): %s", resp.StatusCode, string(respBody))
	}

	if len(respBody) > 0 {
		var errResp domain.ErrorRestResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			if isOcppTagAlreadyExists(respBody) {
				return nil
			}
			return fmt.Errorf("cadastro da tag RFID retornou erro: %s", errResp.Error)
		}
	}

	return nil
}

func isOcppTagAlreadyExists(body []byte) bool {
	var errResp domain.ErrorRestResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return false
	}
	msg := strings.ToLower(errResp.Error)
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "já existe")
}
