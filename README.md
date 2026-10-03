# auth-service

Serviço de autenticação em Go pensado para uma SPA e um conjunto de microsserviços.

A ideia é simples: o navegador nunca vê token. A SPA recebe só um cookie de sessão opaco, e a sessão fica no Redis. Um gateway (BFF) troca essa sessão por um JWT interno de poucos minutos, assinado com Ed25519, e os microsserviços validam esse JWT pelas chaves públicas em `/.well-known/jwks.json`. Serviço falando com serviço usa client credentials.

O projeto está sendo construído em fases curtas. Cada fase só começa quando a anterior está entendida linha por linha.

## Roadmap

- [x] **Fase 1:** esqueleto, config validada, servidor HTTP endurecido, logs com slog, Postgres com migrations, Docker e CI
- [ ] **Fase 2:** cadastro e login com Argon2id, anti-enumeração, sessões no Redis
- [ ] **Fase 3:** rate limit, bloqueio progressivo e log de auditoria
- [ ] **Fase 4:** JWT interno, JWKS e middleware para os microsserviços
- [ ] **Fase 5:** client credentials
- [ ] **Fase 6:** verificação de e-mail e redefinição de senha
- [ ] **Depois:** MFA (TOTP), pentest e lançamento

## Rodando

Você precisa de Go 1.27+ e Docker.

```bash
cp .env.example .env
docker compose up --build
```

Use só letras, números e hífen na senha do `.env`, porque ela vai direto na URL de conexão.

```bash
curl -i localhost:8080/healthz
curl -i localhost:8080/readyz
```

Para rodar fora do Docker, suba só o banco e aponte a variável:

```bash
docker compose up -d postgres
export AUTH_DATABASE_URL="postgres://auth:<senha>@localhost:5432/auth?sslmode=disable"
go run ./cmd/migrate up
go run ./cmd/auth
```

## Configuração

| Variável | Padrão | |
|---|---|---|
| `AUTH_DATABASE_URL` | obrigatória | em produção exige `sslmode=require` ou mais forte |
| `AUTH_ENV` | `development` | `development` ou `production` |
| `AUTH_HTTP_ADDR` | `:8080` | |
| `AUTH_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `AUTH_SHUTDOWN_TIMEOUT` | `15s` | até `1m` |

Se algo estiver errado, o serviço não sobe e lista todos os problemas de uma vez.

## Desenvolvimento

```bash
go test ./...
golangci-lint run
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

O CI roda isso tudo, além do gitleaks para pegar segredo commitado por engano.

## Segurança

Achou alguma falha? Não abra issue pública. Use o [reporte privado de vulnerabilidades](../../security/advisories/new) do GitHub.
