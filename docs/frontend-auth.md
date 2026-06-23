# Frontend de Autenticação — OpenM

Documentação da camada visual e de UX da autenticação, implementada na **issue #13**. Cobre as telas de login/registro, o handler `auth.js`, o cliente `api.js` com refresh automático, e a topbar com indicador de usuário.

## Visão geral

| Camada | Arquivo | Responsabilidade |
|---|---|---|
| Páginas HTML | `openm/frontend/templates/{login,register}.html` | UI dos forms |
| Blueprint Flask | `openm/frontend/routes.py` | Serve `/login`, `/register`, `/logout` |
| Handler de forms | `openm/frontend/static/js/auth.js` | Submit, validação client-side, redirect |
| Cliente HTTP | `openm/frontend/static/js/api.js` | Wrapper `fetch` + refresh automático |
| Helper de bootstrap | `window.OpenMAuth` | `me()` + `logout()` + redirect |

## Fluxo de telas

```
                  ┌─────────────┐
   primeira vez → │  /register  │ (só se ALLOW_REGISTRATION=true)
                  └──────┬──────┘
                         │ submit
                         ▼
                  ┌─────────────┐
                  │  /login     │ ← retorno se registro OK
                  └──────┬──────┘
                         │ POST /api/auth/login
                         ▼
              ┌────────────────────┐
              │ Set-Cookie httpOnly │
              │  openm_access      │
              │  openm_refresh     │
              └────────┬───────────┘
                       │ 302 → /
                       ▼
                  ┌─────────────┐
                  │     /       │ (index.html)
                  └──────┬──────┘
                         │ GET /api/auth/me (bootstrap)
                         ▼
                  ┌─────────────┐
                  │ Topbar mostra│
                  │  user.email  │
                  │  [Sair]      │
                  └──────────────┘
```

## Refresh automático (interceptor 401)

O `api.js` tem um wrapper que detecta `401` em qualquer chamada autenticada e tenta refresh antes de propagar o erro:

```
1. fetch("/api/anything")
2. response.status === 401
3. POST /api/auth/refresh (cookie openm_refresh vai sozinho)
4a. ok → refaz a request original com o novo cookie
4b. fail → redirect /login
```

**Anti-loop**:
- Flag `_retried` na options garante que a retry não entra em loop infinito
- Flag `_refreshing` coalesce múltiplas 401s paralelas num único refresh

**Importante**: chamadas para `/api/auth/login`, `/register`, `/refresh`, `/logout` e `/health` **não** disparam refresh (fazem parte do fluxo de auth).

## Topbar — usuário logado

`index.html` ganhou um bloco `.user-info` na topbar:

```html
<div class="user-info">
    <i class="fa-solid fa-user-circle"></i>
    <span id="user-email"></span>
    <a class="btn icon" id="btn-logout" href="/logout" title="Sair">
        <i class="fa-solid fa-right-from-bracket"></i>
    </a>
</div>
```

O email é populado pelo `App.loadUser()` (chamado em `App.init()`), que faz `GET /api/auth/me` via `OpenMAuth.bootstrap()`. Se falhar, redireciona pra `/login`.

O botão **Sair** aponta pra `/logout` (server-side): handler em `frontend/routes.py` que revoga o refresh token e limpa os cookies. **Não usa AJAX** — server-side garante que o cookie foi removido no navegador.

## Configuração de cookies em produção

Para deploy em HTTPS, defina no `.env` (ou `.env.docker`):

```bash
JWT_COOKIE_SECURE=true
JWT_COOKIE_DOMAIN=.exemplo.com   # opcional, para subdomínios compartilhados
```

Sem `JWT_COOKIE_SECURE=true`, o navegador aceita enviar o cookie em HTTP, expondo o token em redes não confiáveis.

## Como adicionar uma nova página autenticada

1. Crie o template em `openm/frontend/templates/<nome>.html`
2. Adicione a rota em `openm/frontend/routes.py` (ou crie um novo blueprint):

```python
from openm.core.auth import login_required_page
from flask import render_template

@frontend_bp.route("/settings")
@login_required_page
def settings_page():
    return render_template("settings.html")
```

3. Se a página precisa chamar APIs autenticadas, use `OpenMAPI` — o cookie vai automaticamente.

## Troubleshooting

**Sessão expira muito rápido**: confira `JWT_ACCESS_TTL_MINUTES` no `.env` (default 15).

**Cookies não estão sendo setados**: verifique se a response tem `Set-Cookie`. Em dev (HTTP), `JWT_COOKIE_SECURE=false` precisa estar setado, senão o navegador recusa cookies `Secure`.

**Logout não funciona**: confirme que o browser aceita cookies de third-party SameSite=None + Secure. Em produção, defina `JWT_COOKIE_SECURE=true`.

**Frontend redireciona pra /login em loop**: geralmente significa que `/api/auth/me` está falhando. Verifique:
- Cookie `openm_access` existe (DevTools → Application → Cookies)
- Token não está expirado (TTL)
- Usuário existe e está `is_active=true` no banco

## Próximos passos

- Refresh proativo (renovar access aos 14 min se TTL=15min, em vez de esperar 401)
- Logout em todas as sessões (revogar todos os refresh tokens do usuário)
- 2FA (TOTP) para o papel `admin`
- Recuperação de senha por email