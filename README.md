# auth-service

Serviço de autenticação em Go pensado para uma SPA e um conjunto de microsserviços.

A ideia é simples: o navegador nunca vê token. A SPA recebe só um cookie de sessão opaco, e a sessão fica no Redis. Um gateway (BFF) troca essa sessão por um JWT interno de poucos minutos, assinado com Ed25519, e os microsserviços validam esse JWT pelas chaves públicas em `/.well-known/jwks.json`. Serviço falando com serviço usa client credentials.

O projeto está sendo construído em fases curtas. Cada fase só começa quando a anterior está entendida linha por linha.

## Roadmap

- [x] **Fase 1:** esqueleto, config validada, servidor HTTP endurecido, logs com slog, Postgres com migrations, Docker e CI
- [x] **Fase 2:** cadastro e login com Argon2id, anti-enumeração, sessões no Redis
- [x] **Fase 3:** rate limit, bloqueio progressivo e log de auditoria
- [x] **Fase 4:** JWT interno, JWKS e middleware para os microsserviços
- [x] **Fase 5:** client credentials
- [x] **Fase 6:** verificação de e-mail e redefinição de senha
- [x] **Fase 7:** MFA com TOTP e códigos de recuperação
- [ ] **Antes de lançar:** pentest externo e o [checklist de lançamento](#antes-de-lançar)

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
| `POST /v1/auth/login/mfa` | `{"code"}` segunda etapa do login quando o MFA está ativo |
| `GET /v1/auth/me` | dados do usuário logado, incluindo `email_verified` e `mfa_enabled` |
| `POST /v1/auth/email/verify` | `{"token"}` confirma o e-mail |
| `POST /v1/auth/email/resend` | manda outro link de confirmação para quem está logado |
| `POST /v1/auth/password/forgot` | `{"email"}` responde `202` sempre, exista a conta ou não |
| `POST /v1/auth/password/reset` | `{"token", "password"}` troca a senha |
| `POST /v1/auth/mfa/setup` | `{"password"}` gera o segredo e a URL `otpauth://` para o QR code |
| `POST /v1/auth/mfa/enable` | `{"code"}` confirma o primeiro código e devolve os códigos de recuperação |
| `POST /v1/auth/mfa/disable` | `{"password", "code"}` desliga o MFA |

O corpo de cadastro e login é `{"email": "...", "password": "..."}` com `Content-Type: application/json`. A senha precisa ter entre 12 e 128 caracteres.

```bash
curl -i localhost:8080/v1/auth/signup -H 'Content-Type: application/json'   -d '{"email":"ana@example.com","password":"uma-senha-bem-longa"}'
curl -i -c cookies.txt localhost:8080/v1/auth/login -H 'Content-Type: application/json'   -d '{"email":"ana@example.com","password":"uma-senha-bem-longa"}'
curl -i -b cookies.txt localhost:8080/v1/auth/me
```

O cookie é `HttpOnly`, `Secure` e `SameSite=Strict`, e em produção usa o prefixo `__Host-`. O Redis guarda só o SHA-256 do token, então um dump do Redis não serve para sequestrar sessão.

## E-mail e senha esquecida

O cadastro manda um link de confirmação. Se o e-mail já tinha conta, o dono recebe um aviso de "você já tem conta" no lugar, e quem cadastrou não percebe diferença nenhuma.

Os links apontam para a SPA em `AUTH_PUBLIC_URL`:

- `/verificar-email#token=...` vale por 24 horas
- `/redefinir-senha#token=...` vale por 30 minutos

O token vai depois do `#` de propósito. O navegador não manda essa parte para servidor nenhum, então ela não aparece em log de proxy nem vaza no `Referer`. A SPA lê o token de `location.hash` e faz o POST.

Os links são de uso único, e pedir um novo invalida o anterior. Redefinir a senha derruba todas as sessões abertas, libera um bloqueio por senha errada, marca o e-mail como confirmado e manda um aviso de "sua senha foi alterada".

Os e-mails saem por uma fila em segundo plano. Assim o "esqueci a senha" responde no mesmo tempo com ou sem conta, e o tempo de resposta não entrega quais e-mails estão cadastrados. Por enquanto o login não exige e-mail confirmado. A SPA decide o que fazer com `email_verified`.

Em desenvolvimento, o compose sobe o [Mailpit](https://mailpit.axllent.org): todo e-mail cai em `http://localhost:8025`. Fora do Docker e sem `AUTH_SMTP_URL`, os e-mails vão para o log. Em produção o SMTP é obrigatório e precisa de TLS, seja `smtps://` ou STARTTLS.

## Verificação em duas etapas

O usuário logado chama `mfa/setup` com a senha atual. A resposta traz o segredo e uma URL `otpauth://`, que a SPA mostra como QR code. Ele escaneia no autenticador, manda o primeiro código em `mfa/enable` e recebe 10 códigos de recuperação. Esses códigos aparecem uma única vez.

Com o MFA ativo, o login muda:

1. `POST /v1/auth/login` com a senha certa responde `202 {"mfa_required": true}` e um cookie `mfa` de 5 minutos, sem sessão ainda.
2. `POST /v1/auth/login/mfa` com o código do app, ou com um código de recuperação, cria a sessão.

Detalhes que importam:

- Ligar e desligar pedem a senha. Assim, uma sessão roubada não basta para trancar o dono fora da conta.
- Um código só vale uma vez, mesmo dentro da janela de 30 segundos. O mesmo vale para cada código de recuperação.
- Código errado conta para um bloqueio progressivo próprio, separado do bloqueio de senha.
- Redefinir a senha pelo e-mail **não** desliga o MFA. Quem tomar a caixa de e-mail continua precisando do segundo fator.
- O segredo fica cifrado no banco com AES-256-GCM, usando `AUTH_MFA_KEY`. Um dump do banco sem a chave não revela nenhum segredo.

Gere a chave com `openssl rand -base64 32`. Em desenvolvimento, sem ela, o serviço usa uma chave temporária e avisa no log: quem ativar MFA perde o acesso quando o serviço reinicia. Trocar a chave em produção invalida todos os MFAs ativos, então guarde-a como guarda a chave do JWT.

## Tokens para os microsserviços

O serviço escuta em duas portas. A `8080` é pública e atende a SPA. A `8081` é interna e não deve ser exposta para fora da rede dos serviços:

| Rota interna | |
|---|---|
| `GET /.well-known/jwks.json` | chaves públicas para validar os tokens |
| `POST /internal/v1/token` | o BFF troca uma sessão de usuário por um JWT |
| `POST /internal/v1/oauth/token` | um serviço pede um JWT para ele mesmo (client credentials) |

Nenhuma das duas rotas de token é aberta: quem chama precisa ser um cliente cadastrado, autenticado com HTTP Basic (`client_id:client_secret`).

### Clientes

Cada serviço que fala com o auth-service é um cliente com escopos. Para cadastrar, use a CLI:

```bash
go run ./cmd/client create bff session:exchange
go run ./cmd/client create pedidos estoque:ler estoque:escrever
go run ./cmd/client list
go run ./cmd/client revoke cli_xxxxx
```

No Docker é o mesmo binário: `docker compose run --rm --entrypoint /app/client auth create bff session:exchange`.

O segredo aparece uma vez só. No banco fica apenas o SHA-256 dele, o que basta porque o segredo é aleatório e longo, sem o custo de um Argon2 a cada chamada. Revogar corta novas emissões na hora. Os tokens já emitidos continuam valendo até expirar, no máximo `AUTH_JWT_TTL`.

### Sessão de usuário

O BFF precisa do escopo `session:exchange`. Ele pega o cookie de sessão que recebeu do navegador e manda o valor. Nos exemplos, `BFF_ID` e `BFF_SECRET` são o que o `client create` mostrou:

```bash
curl -s localhost:8081/internal/v1/token -u "$BFF_ID:$BFF_SECRET" \
  -H 'Content-Type: application/json' -d '{"session_token":"<valor do cookie>"}'
```

O token sai com `sub` igual ao id do usuário e `client_id` igual ao do BFF. Guarde o JWT por sessão e só troque de novo perto de expirar: a rota aceita até 3000 trocas por minuto por IP.

### Serviço para serviço

```bash
curl -s localhost:8081/internal/v1/oauth/token -u "$PEDIDOS_ID:$PEDIDOS_SECRET" \
  -d grant_type=client_credentials -d 'scope=estoque:ler'
```

Sem `scope`, o token vem com todos os escopos do cliente. Pedir um escopo que o cliente não tem dá `invalid_scope`. Aqui `sub` e `client_id` são o próprio cliente. Os erros seguem a RFC 6749 (`invalid_client`, `invalid_scope`, `unsupported_grant_type`), e o segredo só é aceito no header, nunca no corpo.

### Formato do token

Assinado com Ed25519 (`alg: EdDSA`), com `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `client_id` e, quando houver, `scope`. O `kid` é o thumbprint da chave (RFC 7638).

Token de usuário também traz `amr`, dizendo como a sessão foi aberta (RFC 8176):

| `amr` | |
|---|---|
| `["pwd"]` | só senha |
| `["pwd", "otp", "mfa"]` | senha e código do autenticador |
| `["pwd", "mfa"]` | senha e código de recuperação |

O `amr` é da sessão, não do usuário. Quem liga o MFA continua com a sessão aberta só com senha até fazer login de novo.

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
mux.Handle("POST /estoque/baixa", verifier.Middleware(authn.RequireScope("estoque:escrever", baixa)))
mux.Handle("POST /conta/pix", verifier.Middleware(authn.RequireMFA(pix)))
```

Dentro do handler, `authn.ClaimsFrom(r.Context())` devolve as claims. `claims.IsService()` diz se quem chamou foi um serviço ou um usuário via BFF, e `RequireScope` responde `403` com `insufficient_scope` quando falta permissão. Para uma rota que exige MFA, use `authn.RequireMFA`: sem `mfa` no `amr`, ela responde `401` com `insufficient_user_authentication` (RFC 9470), e a SPA pode pedir para o usuário entrar de novo com o segundo fator. Token de serviço nunca passa por ela. As chaves ficam em cache por 10 minutos. Um `kid` desconhecido força uma nova busca, mas no máximo uma a cada 30 segundos, para um token inventado não virar enxurrada de requisições no JWKS. Se o JWKS cair, as chaves que já estão em cache continuam valendo.

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
| `AUTH_PUBLIC_URL` | `http://localhost:5173` | endereço da SPA usado nos links, obrigatório e `https` em produção |
| `AUTH_SMTP_URL` | vazio | `smtp://user:senha@host:587` ou `smtps://...:465`, obrigatório em produção |
| `AUTH_MAIL_FROM` | `auth-service <no-reply@localhost>` | remetente, obrigatório em produção |
| `AUTH_MFA_KEY` | vazio | 32 bytes em base64 para cifrar os segredos de MFA, obrigatória em produção |
| `AUTH_MFA_ISSUER` | `auth-service` | nome que aparece no app autenticador |
| `AUTH_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `AUTH_SHUTDOWN_TIMEOUT` | `15s` | até `1m` |

Se algo estiver errado, o serviço não sobe e lista todos os problemas de uma vez.

## Desenvolvimento

```bash
go test ./...
golangci-lint run
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Os testes dos repositórios Postgres ficam em `internal/integration` e só rodam com `AUTH_TEST_DATABASE_URL` definida. Eles apagam as tabelas, então use um banco separado, nunca o de desenvolvimento:

```bash
docker compose up -d postgres
docker compose exec postgres createdb -U auth auth_test
AUTH_TEST_DATABASE_URL="postgres://auth:<senha>@localhost:5432/auth_test?sslmode=disable" go test -v ./internal/integration/
```

O CI roda tudo isso, inclusive a integração com um Postgres de serviço, além do gitleaks para pegar segredo commitado por engano.

## Antes de lançar

O código está pronto, mas lançar depende de coisas que não moram no repositório.

**Infra**
- [ ] TLS terminando no proxy, com o IP dele em `AUTH_TRUSTED_PROXIES`
- [ ] Porta `8081` alcançável só pela rede interna (network policy ou security group), nunca pela internet
- [ ] Postgres com `sslmode=verify-full`, backup automático e restauração testada
- [ ] Redis com `rediss://`, AOF ligado e `maxmemory-policy noeviction`. Se o Redis despejar chaves sob pressão, somem sessões e, pior, os contadores de bloqueio
- [ ] Migrations rodando antes do deploy (`/app/migrate up`)

**Segredos**
- [ ] `AUTH_JWT_KEY_FILE`, `AUTH_MFA_KEY` e a senha do SMTP num cofre, não em variável solta
- [ ] Backup da `AUTH_MFA_KEY`. Perder essa chave tranca todo mundo que usa MFA
- [ ] Cliente do BFF criado em produção (`client create bff session:exchange`)

**E-mail**
- [ ] SPF, DKIM e DMARC no domínio do `AUTH_MAIL_FROM`. Sem eles os links caem no spam
- [ ] SPA com as rotas `/verificar-email`, `/redefinir-senha` e `/esqueci-a-senha` lendo o token do `#`

**Operação**
- [ ] Alertas para picos de `login.failed`, `login.mfa_failed`, `client.auth_failed` e para o log "rate limit excedido"
- [ ] Prazo de retenção da `audit_events` definido (ela guarda e-mail e IP, então entra na LGPD) e um job de limpeza
- [ ] CI verde, incluindo `-race` e integração

**Pentest**
- [ ] Teste externo cobrindo as rotas públicas, a troca de sessão por token, o client credentials e o login com MFA

## Segurança

Achou alguma falha? Não abra issue pública. Use o [reporte privado de vulnerabilidades](../../security/advisories/new) do GitHub.
