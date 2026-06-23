# Autenticação — OpenM

Esta página descreve o sistema de autenticação baseado em **JWT (JSON Web Tokens)** com **access token + refresh token**, implementado nas issues #1 (backend) e #13 (frontend + cookies httpOnly + proteção de APIs).

## Visão geral

- **Access token**: TTL curto (15 min por padrão), enviado em toda requisição autenticada como `Authorization: Bearer <token>`.
- **Refresh token**: TTL longo (7 dias por padrão), usado **apenas** para obter um novo par de tokens via `/api/auth/refresh`.
- **Algoritmo**: `HS256` com chave simétrica (`JWT_SECRET`, com fallback para `SECRET_KEY`).
- **Blacklist**: refresh tokens revogados (logout / rotação) vão para a tabela `revoked_tokens` (Postgres). Access tokens são **stateless** (não precisam de blacklist — basta deixar expirar).
- **Hash de senha**: `bcrypt` via `passlib` (rounds=12).

## Fluxo

```
┌────────┐                                    ┌────────┐
│ Cliente│                                    │  API   │
└───┬────┘                                    └───┬────┘
    │  POST /api/auth/login {email, password}     │
    │ ─────────────────────────────────────────► │
    │                                             │
    │ ◄── 200 {access_token, refresh_token} ──── │
    │                                             │
    │  GET /api/investigations                    │
    │  Authorization: Bearer <access_token>       │
    │ ─────────────────────────────────────────► │
    │                                             │
    │ ◄── 401 (access expirou) ────────────────── │
    │                                             │
    │  POST /api/auth/refresh {refresh_token}     │
    │ ─────────────────────────────────────────► │
    │   ↳ revoga o refresh_token antigo           │
    │   ↳ emite novo par (rotação)                │
    │ ◄── 200 {novo access, novo refresh} ────── │
```

## Endpoints

| Método | Rota | Auth | Rate limit | Descrição |
|---|---|---|---|---|
| `POST` | `/api/auth/register` | pública | 3/hora | Cria usuário. **Bloqueado** quando `ALLOW_REGISTRATION=false`. |
| `POST` | `/api/auth/login` | pública | 5/min | Autentica e devolve par de tokens. |
| `POST` | `/api/auth/refresh` | refresh token | 30/min | Rotaciona o refresh token. |
| `POST` | `/api/auth/logout` | refresh token | 30/min | Revoga o refresh token (idempotente). |
| `GET` | `/api/auth/me` | bearer access | — | Perfil do usuário autenticado. |

### Exemplos

**Login**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"supersecret"}'
```
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_at": "2026-06-30T13:00:00+00:00",
  "refresh_jti": "5f2a...",
  "user": {"id": 1, "email": "alice@example.com", "role": "analyst"}
}
```

**Acessar rota protegida**
```bash
curl http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer <access_token>"
```

**Renovar**
```bash
curl -X POST http://localhost:5000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

**Logout**
```bash
curl -X POST http://localhost:5000/api/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Claims do JWT

```json
{
  "sub": "1",
  "email": "alice@example.com",
  "role": "analyst",
  "type": "access",          // ou "refresh"
  "iss": "openm",
  "aud": "openm-api",
  "iat": 1719150000,
  "exp": 1719150900,
  "jti": "5f2a..."
}
```

## Configuração

Todas as variáveis têm defaults razoáveis e podem ser sobrescritas via `.env`:

| Variável | Default | Descrição |
|---|---|---|
| `JWT_SECRET` | `SECRET_KEY` | Chave simétrica HS256. **Obrigatória** em produção. |
| `JWT_ALGORITHM` | `HS256` | Algoritmo de assinatura. |
| `JWT_ACCESS_TTL_MINUTES` | `15` | TTL do access token. |
| `JWT_REFRESH_TTL_DAYS` | `7` | TTL do refresh token. |
| `JWT_ISSUER` | `openm` | Claim `iss`. |
| `JWT_AUDIENCE` | `openm-api` | Claim `aud`. |
| `ALLOW_REGISTRATION` | `false` | Habilita `POST /api/auth/register`. **Default fechado em produção**. |
| `JWT_COOKIE_ACCESS_NAME` | `openm_access` | Nome do cookie httpOnly de access. |
| `JWT_COOKIE_REFRESH_NAME` | `openm_refresh` | Nome do cookie httpOnly de refresh. |
| `JWT_COOKIE_SECURE` | `false` | Marca `Secure` nos cookies. **Deve ser `true` em produção (HTTPS)**. |
| `JWT_COOKIE_DOMAIN` | `None` | Domínio opcional dos cookies (None = host atual). |

## Boas práticas para o cliente

- Guarde o **access token em memória** (variável JS), nunca em `localStorage`.
- Guarde o **refresh token em cookie httpOnly** + `Secure` + `SameSite=Lax` (proteção contra XSS/CSRF).
- Implemente **renovação silenciosa** antes do access expirar (ex.: aos 14 min se TTL=15min).
- Trate `401` globalmente redirecionando para `/login` quando o refresh também falhar.
- **Nunca** loggue tokens brutos.

## Decisões de segurança

- **Mensagens genéricas** em `/login`: a mesma resposta para "email não existe" e "senha errada" evita enumeração de usuários.
- **Rate limit agressivo** em `/login` (5/min por IP) mitiga brute-force.
- **Token rotation**: cada `/refresh` invalida o refresh apresentado e emite um novo. Reuso de refresh revogado retorna `401`.
- **Senha mínima de 8 caracteres** validada no payload.
- **Email validado e normalizado** (`email-validator`, com `check_deliverability=False` para evitar latência em testes).
- **BCrypt rounds=12** (default seguro em 2025).
- **JWT_SECRET** lido com fallback para `SECRET_KEY`; em produção defina um valor próprio e forte.
- **Cookies httpOnly + SameSite**: tokens de sessão nunca são acessíveis por JavaScript, mitigando XSS. `SameSite=Lax` no access e `Strict` no refresh mitiga CSRF.

## Cookies httpOnly (issue #13)

Desde a issue #13, os endpoints `/api/auth/login`, `/refresh` e `/logout` **também** setam cookies httpOnly além de retornarem os tokens no JSON. O frontend usa os cookies (não tem como o JS anexar `Authorization` se ele não tem o token em mãos).

### Nomes e flags

| Cookie | Path | SameSite | Secure (prod) | TTL |
|---|---|---|---|---|
| `openm_access` | `/` | `Lax` | true | 15 min (`JWT_ACCESS_TTL_MINUTES`) |
| `openm_refresh` | `/` | `Strict` | true | 7 dias (`JWT_REFRESH_TTL_DAYS`) |

Ambos com `HttpOnly` (JS nunca consegue ler) e `path=/`.

### Como o backend resolve o token

`@require_auth` e `login_required_page` leem **em ordem**:
1. Header `Authorization: Bearer <token>` (uso externo / API / testes)
2. Cookie `openm_access` (uso do frontend)

`/refresh` e `/logout` leem **em ordem**:
1. Body JSON `{"refresh_token": "..."}` (uso externo / testes)
2. Cookie `openm_refresh` (uso do frontend)

### Em produção

Defina **obrigatoriamente** `JWT_COOKIE_SECURE=true` no `.env`. Sem isso, o navegador aceita mandar o cookie em HTTP puro, expondo o token em redes não confiáveis.

```bash
# .env (produção)
JWT_COOKIE_SECURE=true
```

## Como adicionar uma rota protegida (issue #13)

Todas as rotas em `/api/*` (exceto `/api/auth/*`) DEVEM usar `@require_auth`:

```python
from openm.core.auth import require_auth, require_role

@my_bp.route("/whatever", methods=["POST"])
@require_auth           # sempre
@require_role("admin")  # opcional: restringe por papel
def my_view():
    from flask import g
    # g.user e g.role estão disponíveis
    ...
```

Para **páginas HTML** (servidas pelo Flask, não pela API), use `login_required_page`:

```python
from openm.core.auth import login_required_page
from flask import render_template

@frontend_bp.route("/settings")
@login_required_page      # redireciona pra /login se sem sessão
def settings_page():
    return render_template("settings.html")
```

## Próximos passos

- Migração para algoritmo assimétrico (RS256) quando houver múltiplos serviços consumindo os tokens.
- Audit log: logar tentativas falhas de login e logouts.
- Refresh sliding window: renovar access token em chamadas autenticadas próximas da expiração.
- CSRF token explícito para mutations feitas via cookies (mitigação complementar ao SameSite).
- Recuperação de senha por email.
