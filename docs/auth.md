# Autenticação — OpenM

Esta página descreve o sistema de autenticação baseado em **JWT (JSON Web Tokens)** com **access token + refresh token**, implementado na issue #1.

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

## Próximos passos

- Issue #2 — Multi-usuário: investigações por dono (`user_id` em `investigations`).
- Issue #3 — RBAC: aplicar `@require_role(...)` em rotas sensíveis.
- Issue #4 — Audit log: logar tentativas falhas de login e logouts.
- Migração para algoritmo assimétrico (RS256) quando houver múltiplos serviços consumindo os tokens.
