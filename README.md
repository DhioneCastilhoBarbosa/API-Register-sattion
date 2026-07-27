# cve-registration-api

API em Go para o formulário de cadastro de carregadores, que orquestra:

1. Checagem de licença/chave de acesso na API de Licenças
   (`api-licenca.intelbras-cve-pro.com.br`)
2. Resolução dos e-mails autorizados em `user_pk` na API CVE-PRO
   (`cs-test.intelbras-cve-pro.com.br`)
3. Cadastro do chargepoint (`POST /api/v1/chargepoints`)
4. Cadastro das tags RFID, se solicitado (`POST /api/v1/ocpptags`)
5. Persistência de cada solicitação no Postgres, com busca por nome, e-mail,
   número de série ou status

## Estrutura

```
cmd/api            → ponto de entrada (main.go)
cmd/hashpassword    → utilitário pra gerar hash bcrypt (cadastro manual do 1º usuário do painel)
internal/config     → carrega e valida o .env
internal/domain     → modelos (formulário, chargepoint, licença, etc.)
internal/cveclient   → cliente HTTP da API CVE-PRO (login automático, chargepoints, ocpptags, usuários)
internal/licenseclient → cliente HTTP da API de Licenças
internal/auth        → tokens do painel/formulário (login próprio da ferramenta)
internal/repository  → Postgres (solicitações + usuários do painel)
internal/service      → orquestração do fluxo completo
internal/handler      → HTTP handlers
migrations            → schema do Postgres
```

## Como rodar

### 1) Banco (manual)

O Compose **não** sobe Postgres. Provisione o banco e informe em `DATABASE_URL`.
As migrations em `migrations/*.sql` rodam **automaticamente** na subida da API.

### 2) Ambiente

Copie `.env.example` para `.env` e preencha:

- `DATABASE_URL` — host do Postgres (não use `localhost` se a API rodar em Docker; use IP/`host.docker.internal`)
- `CVE_API_KEY`, `CVE_LOGIN_EMAIL`, `CVE_LOGIN_PASSWORD`, `CVE_TENANT_PK`
- `LICENSE_LOGIN_EMAIL`, `LICENSE_LOGIN_PASSWORD`
- `JWT_SECRET` (string longa e aleatória)

### 3) Local (sem Docker)

```bash
go mod tidy
go run ./cmd/api
```

### 4) Produção (Docker — só a API)

```bash
docker compose up -d --build
```

A API escuta em `http://localhost:8080` (ou a porta de `PORT` no `.env`).

### 5) Primeiro usuário do painel

```bash
go run ./cmd/hashpassword "sua-senha-aqui"
psql "$DATABASE_URL" -c "INSERT INTO panel_users (email, password_hash, enabled) VALUES ('voce@empresa.com', '<hash>', true);"
```

## Rotas

- `POST /auth/login` — `{ "email", "password" }` → `{ "token" }`. Use esse
  token como `Authorization: Bearer <token>` nas rotas abaixo.
- `POST /registrations` — recebe o `RegistrationForm` (ver
  `internal/domain/registration.go`) e roda o fluxo completo.
- `GET /registrations?q=termo` — busca por nome, e-mail, número de série ou
  status.

## Pontos em aberto (precisam de confirmação sua / do suporte Intelbras)

1. **Formato da resposta do login da API de Licenças** — o Swagger só
   documenta como `additionalProperties: string`; assumi um campo
   `"token"` em `internal/licenseclient/client.go`. Teste contra o ambiente
   real e ajuste se o nome for outro.
2. **Como uma licença se liga ao formulário** — `/licencas` só filtra por
   `codigo_compra`/`codigo`, sem e-mail ou número de série. O serviço usa
   `/buscar-chave?email=` como primeira aproximação
   (`internal/service/registration_service.go`), mas confirme se é isso
   mesmo ou se o fluxo certo é outro (ex: 1 licença por compra, e não por
   carregador).
3. **Latitude/Longitude** — o backend só recebe o que o front mandar (via
   ViaCEP + geocoder). Não há geocodificação no backend.
