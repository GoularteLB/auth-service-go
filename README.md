# auth-service

Serviço de autenticação em Go pensado para uma SPA e um conjunto de microsserviços.

A ideia é simples: o navegador nunca vê token. A SPA recebe só um cookie de sessão opaco, e a sessão fica no Redis. Um gateway (BFF) troca essa sessão por um JWT interno de poucos minutos, assinado com Ed25519, e os microsserviços validam esse JWT pelas chaves públicas em `/.well-known/jwks.json`. Serviço falando com serviço usa client credentials.

O projeto está sendo construído em fases curtas. Cada fase só começa quando a anterior está entendida linha por linha.

## Roadmap

- [x] **Fase 1:** esqueleto, config validada, servidor HTTP endurecido, logs com slog, Postgres com migrations, Docker e CI
- [x] **Fase 2:** cadastro e login com Argon2id, anti-enumeração, sessões no Redis
- [x] **Fase 3:** rate limit, bloqueio progressivo e log de auditoria
- [x] **Fase 4:** JWT interno, JWKS e middleware para os microsserviços
- [ ] **Fase 5:** client credentials
- [ ] **Fase 6:** verificação de e-mail e redefinição de senha
- [ ] **Depois:** MFA (TOTP), pentest e lançamento

## Rodando

Você precisa de Go 1.27+ e Docker.

```bash
cp .env.example .env
docker compose up --build
```

Use só letras, números e hífen nas senhas do `.env`, porque elas vão direto nas URLs de conexão.

```bash
curl -i localhost:8080/healthz
curl -i localhost:8080/readyz
```

Para rodar fora do Docker, suba só o banco e o Redis e aponte as variáveis:

```bash
docker compose up -d postgres redis
export AUTH_DATABASE_URL="postgres://auth:<senha>@localhost:5432/auth?sslmode=disable"
export AUTH_REDIS_URL="redis://:<senha-do-redis>@localhost:6379/0"
go run ./cmd/migrate up
go run ./cmd/auth
```

## Endpoints

| Rota | |
|---|---|
| `POST /v1/auth/signup` | cria a conta e responde `202`, mesmo se o e-mail já existir |
| `POST /v1/auth/login` | responde `204` com o cookie de sessão, ou `401` |
| `POST /v1/auth/logout` | apaga a sessão e o cookie |
| `GET /v1/auth/me` | dados do usuário logado |

O corpo de cadastro e login é `{"email": "...", "password": "..."}` com `Content-Type: application/json`. A senha precisa ter entre 12 e 128 caracteres.

```bash
curl -i localhost:8080/v1/auth/signup -H 'Content-Type: application/json'   -d '{"email":"ana@example.com","password":"uma-senha-bem-longa"}'
curl -i -c cookies.txt localhost:8080/v1/auth/login -H 'Content-Type: application/json'   -d '{"email":"ana@example.com","password":"uma-senha-bem-longa"}'
curl -i -b cookies.txt localhost:8080/v1/auth/me
```

O cookie é `HttpOnly`, `Secure` e `SameSite=Strict`, e em produção usa o prefixo `__Host-`. O Redis guarda só o SHA-256 do token, então um dump do Redis não serve para sequestrar sessão.

## Tokens para os microsserviços

O serviço escuta em duas portas. A `8080` é pública e atende a SPA. A `8081` é interna e não deve ser exposta para fora da rede dos serviços:

| Rota interna | |
|---|---|
| `GET /.well-known/jwks.json` | chaves públicas para validar os tokens |
| `POST /internal/v1/token` | troca uma sessão por um JWT de 5 minutos |

O BFF pega o cookie de sessão que recebeu do navegador e manda o valor:

```bash
curl -s localhost:8081/internal/v1/token -H 'Content-Type: application/json' \
  -d '{"session_token":"<valor do cookie>"}'
```

A resposta traz `access_token`, `token_type` e `expires_in`. O token é assinado com Ed25519 (`alg: EdDSA`) e leva `iss`, `sub` (id do usuário), `aud`, `iat`, `nbf`, `exp` e `jti`. O `kid` é o thumbprint da chave (RFC 7638).

Por enquanto quem protege a troca é a rede: qualquer um que alcance a `8081` com uma sessão válida consegue um token. A Fase 5 coloca client credentials na frente disso.

### Validando nos microsserviços

O pacote `pkg/authn` é público justamente para os outros serviços importarem:

```go
keys, err := authn.NewRemoteKeys("http://auth-service:8081/.well-known/jwks.json")
if err != nil {
	log.Fatal(err)
}
verifier := &authn.Verifier{
	Keys:     keys,
	Issuer:   "auth-service",
	Audience: "internal",
	Leeway:   30 * time.Second,
}
mux.Handle("GET /pedidos", verifier.Middleware(pedidos))
```

Dentro do handler, `authn.ClaimsFrom(r.Context())` devolve as claims. As chaves ficam em cache por 10 minutos. Um `kid` desconhecido força uma nova busca, mas no máximo uma a cada 30 segundos, para um token inventado não virar enxurrada de requisições no JWKS. Se o JWKS cair, as chaves que já estão em cache continuam valendo.

### Chaves e rotação

```bash
go run ./cmd/keygen secrets/jwt-2026-10.pem
```

Isso gera a privada e a `.pub.pem` ao lado. Em desenvolvimento, sem `AUTH_JWT_KEY_FILE`, o serviço cria uma chave temporária a cada boot e avisa no log. Em produção ele não sobe sem a chave.

Para rotacionar, gere a chave nova, aponte `AUTH_JWT_KEY_FILE` para ela e coloque a `.pub.pem` da antiga em `AUTH_JWT_PREVIOUS_KEY_FILES`. As duas aparecem no JWKS, e os tokens antigos continuam valendo até expirar. Depois de alguns minutos, a antiga já pode sair.

## Proteção contra força bruta

São duas camadas, as duas no Redis:

- **Por IP:** 10 logins por minuto e 10 cadastros por hora. Passou disso, `429` com `Retry-After`.
- **Por conta:** a partir da 5ª senha errada seguida, o e-mail fica bloqueado por 1 minuto, e o tempo dobra a cada nova falha até 15 minutos. Um login certo zera a contagem, e uma hora sem erro também. O bloqueio vale igual para e-mail que não existe, senão ele denunciaria quais contas existem.

As chaves no Redis são hashes, então IP e e-mail não ficam lá em texto puro.

Atrás de proxy ou BFF, informe os IPs dele em `AUTH_TRUSTED_PROXIES`. Sem isso o `X-Forwarded-For` é ignorado, e todo mundo atrás do proxy divide o mesmo limite.

## Auditoria

Cadastro, cadastro duplicado, login certo, login errado, login bloqueado e logout viram uma linha em `audit_events` no Postgres, com IP, user agent e request id. Se a gravação falhar, o login segue e o erro vai para o log. O excesso de requisições por IP fica só no log, para um ataque não sair enchendo a tabela.

## Configuração

| Variável | Padrão | |
|---|---|---|
| `AUTH_DATABASE_URL` | obrigatória | em produção exige `sslmode=require` ou mais forte |
| `AUTH_REDIS_URL` | obrigatória | em produção exige `rediss://` |
| `AUTH_SESSION_TTL` | `12h` | entre `5m` e `720h` |
| `AUTH_TRUSTED_PROXIES` | vazio | IPs ou CIDRs separados por vírgula |
| `AUTH_ENV` | `development` | `development` ou `production` |
| `AUTH_HTTP_ADDR` | `:8080` | listener público |
| `AUTH_INTERNAL_ADDR` | `:8081` | listener interno, precisa ser diferente do público |
| `AUTH_JWT_KEY_FILE` | vazio | PEM PKCS#8 Ed25519, obrigatória em produção |
| `AUTH_JWT_PREVIOUS_KEY_FILES` | vazio | chaves antigas ainda publicadas no JWKS, separadas por vírgula |
| `AUTH_JWT_ISSUER` | `auth-service` | |
| `AUTH_JWT_AUDIENCE` | `internal` | |
| `AUTH_JWT_TTL` | `5m` | entre `1m` e `15m` |
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
