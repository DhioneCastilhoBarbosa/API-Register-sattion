package licenseclient

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

// Client fala com a API de Licenças (api-licenca.intelbras-cve-pro.com.br).
// É separada da CVE-PRO — login e token próprios (Bearer via header
// Authorization).
type Client struct {
	baseURL    string
	email      string
	password   string
	httpClient *http.Client

	mu    sync.Mutex
	token string
}

func New(baseURL, email, password string) *Client {
	return &Client{
		baseURL:  baseURL,
		email:    email,
		password: password,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login(ctx)
}

func (c *Client) login(ctx context.Context) error {
	body, _ := json.Marshal(domain.LicenseLoginRequest{
		Email: c.email,
		Senha: c.password,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login na API de licenças: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login na API de licenças falhou (status %d): %s", resp.StatusCode, string(respBody))
	}

	// O Swagger descreve a resposta como um map genérico
	// (additionalProperties: string) — assumindo a chave "token" abaixo.
	// Confirme contra o ambiente de teste e ajuste se o nome for outro.
	var raw map[string]string
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return fmt.Errorf("parse da resposta de login: %w", err)
	}
	token, ok := raw["token"]
	if !ok {
		return fmt.Errorf("resposta de login sem campo 'token': %s", string(respBody))
	}

	c.token = token
	return nil
}

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
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
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

// BuscarChavePorEmail consulta GET /buscar-chave?email=... — retorna nil
// (sem erro) se não encontrar nenhuma chave para o e-mail.
func (c *Client) BuscarChavePorEmail(ctx context.Context, email string) (*domain.Chave, error) {
	path := "/buscar-chave?" + url.Values{"email": {email}}.Encode()
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("buscar-chave falhou (status %d): %s", resp.StatusCode, string(b))
	}

	var chave domain.Chave
	if err := json.NewDecoder(resp.Body).Decode(&chave); err != nil {
		return nil, err
	}
	return &chave, nil
}

// ListarLicencas consulta GET /licencas, filtrando por código da compra
// e/ou código da licença (os únicos filtros documentados no Swagger).
//
// ATENÇÃO: nenhuma rota documentada filtra licença por e-mail ou número de
// série do carregador diretamente — ainda não está claro como amarrar "qual
// licença usar" a partir do formulário. Confirme com quem administra essa
// API antes de usar isso em produção.
func (c *Client) ListarLicencas(ctx context.Context, codigoCompra, codigo string) ([]domain.License, error) {
	q := url.Values{}
	if codigoCompra != "" {
		q.Set("codigo_compra", codigoCompra)
	}
	if codigo != "" {
		q.Set("codigo", codigo)
	}
	path := "/licencas"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("listar licenças falhou (status %d): %s", resp.StatusCode, string(b))
	}

	var licencas []domain.License
	if err := json.NewDecoder(resp.Body).Decode(&licencas); err != nil {
		return nil, err
	}
	return licencas, nil
}

// BuscarLicencaDisponivelPorEmail procura em GET /licencas uma licença
// utilizável para o e-mail (status Coringa ou Ativada). Isso é o que a
// CVE-PRO espera em licenseCode — NÃO a chave CVE-... de /buscar-chave.
func (c *Client) BuscarLicencaDisponivelPorEmail(ctx context.Context, email string) (*domain.License, error) {
	licencas, err := c.ListarLicencas(ctx, "", "")
	if err != nil {
		return nil, err
	}

	email = strings.TrimSpace(strings.ToLower(email))
	var ativada *domain.License
	for i := range licencas {
		l := &licencas[i]
		if strings.TrimSpace(strings.ToLower(l.Email)) != email {
			continue
		}
		if l.Status == "Coringa" || l.Coringa {
			cp := *l
			return &cp, nil
		}
		if l.Status == "Ativada" && ativada == nil {
			cp := *l
			ativada = &cp
		}
	}
	return ativada, nil
}

// BuscarLicencaPorCodigo consulta GET /licencas?codigo=...
func (c *Client) BuscarLicencaPorCodigo(ctx context.Context, codigo string) (*domain.License, error) {
	licencas, err := c.ListarLicencas(ctx, "", codigo)
	if err != nil {
		return nil, err
	}
	if len(licencas) == 0 {
		return nil, nil
	}
	l := licencas[0]
	return &l, nil
}
