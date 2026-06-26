# RBAC — Controle de Acesso por Papel (issue #3)

Esta página descreve o sistema de **controle de acesso baseado em papéis (RBAC)** do OpenM: três papéis (`admin`, `analyst`, `viewer`) com permissões distintas, aplicados no backend via decorators e refletidos no frontend via atributos `data-roles`.

## Visão geral

| Papel | Quem é | O que pode |
|---|---|---|
| **admin** | Responsável pela plataforma | Tudo, incluindo gerenciar outros usuários |
| **analyst** | Investigador OSINT | Criar/editar investigations, entidades, transforms e chaves de API |
| **viewer** | Stakeholder / observador | Apenas leitura de investigations e do grafo |

A regra de ouro: **toda checagem de segurança real acontece no backend**. O frontend usa `data-roles` apenas para esconder/desabilitar a UI — o servidor sempre revalida o role do token em cada request.

## Modelo de dados

Tabela `users` (Postgres):

```python
class User(db.Model):
    id = ...
    email = ...
    password_hash = ...
    role = db.Column(db.String(32), nullable=False, default="analyst")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
```

Roles válidos são definidos em `openm/models/user.py`:

```python
VALID_ROLES = ("admin", "analyst", "viewer")
```

Manter como `String` (em vez de `Enum`) deixa o sistema tolerante à adição de novos papéis sem migração de schema — basta atualizar `VALID_ROLES`.

## JWT e claim `role`

O access token inclui a claim `role` no payload, decodificada em `core/auth.py:encode_token`:

```json
{
  "sub": "1",
  "email": "user@example.com",
  "role": "analyst",
  "type": "access",
  "iss": "openm",
  "aud": "openm-api",
  "iat": 1719220000,
  "exp": 1719220900,
  "jti": "abc123"
}
```

O decorator `@require_auth` popula `g.user` e `g.role` em cada request, e `@require_role(...)` valida o role antes de chamar o handler.

## Matriz de permissões

| Endpoint | viewer | analyst | admin |
|---|:---:|:---:|:---:|
| `GET    /api/auth/me` | ✓ | ✓ | ✓ |
| `GET    /api/investigations` | ✓ | ✓ | ✓ |
| `GET    /api/investigations/<id>` | ✓ | ✓ | ✓ |
| `POST   /api/investigations` | ✗ | ✓ | ✓ |
| `PUT    /api/investigations/<id>` | ✗ | ✓ | ✓ |
| `POST   /api/investigations/<id>/archive` | ✗ | ✓ | ✓ |
| `POST   /api/investigations/<id>/unarchive` | ✗ | ✓ | ✓ |
| `DELETE /api/investigations/<id>` | ✗ | ✓ | ✓ |
| `GET    /api/subgraph/<id>` | ✓ | ✓ | ✓ |
| `GET    /api/transforms/<type>` | ✓ | ✓ | ✓ |
| `POST   /api/entity` | ✗ | ✓ | ✓ |
| `PATCH  /api/entity/<id>` | ✗ | ✓ | ✓ |
| `DELETE /api/entity/<id>` | ✗ | ✓ | ✓ |
| `POST   /api/edge` | ✗ | ✓ | ✓ |
| `DELETE /api/edge/<id>` | ✗ | ✓ | ✓ |
| `POST   /api/run_transform` | ✗ | ✓ | ✓ |
| `GET    /api/keys` | ✗ | ✓ | ✓ |
| `POST   /api/keys` | ✗ | ✓ | ✓ |
| `DELETE /api/keys/<id>` | ✗ | ✓ | ✓ |
| `GET    /api/admin/users` | ✗ | ✗ | ✓ |
| `PATCH  /api/admin/users/<id>/role` | ✗ | ✗ | ✓ |
| `PATCH  /api/admin/users/<id>/active` | ✗ | ✗ | ✓ |

**Viewer** é o papel mais restritivo: só consegue ler investigations e ver o subgrafo. Não consegue ver a lista de chaves de API, criar entidades ou rodar transforms. Isso reduz superfície de ataque para contas comprometidas com privilégios mínimos.

**Analyst** é o papel operacional padrão: faz tudo, exceto gerenciar outros usuários. É o role default no registro (`role="analyst"`).

**Admin** tem acesso total. Use com moderação.

## Implementação no backend

### Decorators

Em `openm/core/auth.py`:

```python
def require_auth(fn):
    """Valida o access token, popula g.user e g.role."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = _extract_bearer()
        if not token:
            return jsonify({"error": "missing bearer token"}), 401
        # ... decodifica e popula g.user / g.role
        return fn(*args, **kwargs)
    return wrapper

def require_role(*allowed):
    """Exige um dos papéis. Usar sempre após @require_auth."""
    invalid = [r for r in allowed if r not in VALID_ROLES]
    if invalid:
        raise ValueError(f"Unknown roles: {invalid}")
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if g.role not in allowed:
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)
        return decorator
    return decorator
```

### Exemplo de uso

```python
@entities_bp.route("/entity", methods=["POST"])
@require_auth                  # 1. valida JWT
@require_role("admin", "analyst")   # 2. valida role
def create_entity():
    # ... handler
```

A ordem importa: `@require_auth` **sempre** antes de `@require_role`. Sem auth, a request é rejeitada com 401; com auth mas sem role, é rejeitada com 403.

### Blueprint `/api/admin/*`

Endpoints exclusivos de admin, em `openm/api/admin.py`:

- `GET    /api/admin/users` — lista todos os usuários
- `PATCH  /api/admin/users/<id>/role` — altera o role (`admin`/`analyst`/`viewer`)
- `PATCH  /api/admin/users/<id>/active` — ativa ou desativa uma conta

**Proteções automáticas:**

1. Admin **não pode rebaixar/desativar a si mesmo** (evita lock-out por acidente).
2. Não é permitido rebaixar o **último admin ativo** (defesa contra race condition).

Erros retornam HTTP 409 com mensagem explicativa (`admin cannot demote themselves` / `cannot demote the last active admin`).

## Implementação no frontend

### Helper `OpenMPermissions`

`openm/frontend/static/js/permissions.js` expõe:

```js
OpenMPermissions.can(role, 'investigation:create')  // true | false
OpenMPermissions.applyRoleGates(user)               // esconde elementos sem data-roles
```

As `actions` aceitas são strings com namespace `recurso:verbo` (`investigation:create`, `entity:delete`, `user:set-role`, etc.). A lista completa está no próprio arquivo.

### Atributo `data-roles`

Botões e elementos da UI marcam quais roles podem visualizá-los:

```html
<button id="btn-create-inv" data-roles="admin,analyst">Nova Investigação</button>
<button id="btn-save-key"   data-roles="admin,analyst">Salvar Chave</button>
<button id="btn-clear"      data-roles="admin,analyst">Limpar grafo</button>
```

Ao carregar, `App.loadUser()` chama `applyRoleGates(user)`, que esconde os elementos cujo `data-roles` não inclui o role do usuário. **Viewer não vê esses botões** — mas a UI ainda tenta respeitar a navegação (não bloqueia navegação, apenas esconde ações de escrita).

### Badge de role na topbar

Ao lado do email do usuário, um badge colorido indica o role atual:

- 🔴 **admin** (vermelho)
- 🔵 **analyst** (azul)
- ⚪ **viewer** (cinza)

Definido em `style.css` via `.role-badge[data-role="..."]`.

## Garantias de segurança

1. **Defense in depth**: o backend sempre revalida o role no token, mesmo que a UI esconda o botão. Viewer que chamar `POST /api/entity` via curl recebe 403.
2. **Tokens auto-contidos**: o role fica no JWT, então não há lookup extra no DB a cada request. Trocar o role de um usuário no DB só tem efeito no próximo login (após o access token expirar).
3. **403 neutro**: a mensagem de erro é sempre `{"error": "forbidden"}` — não vaza qual role era necessário.
4. **Lock-out impossível**: admin não pode rebaixar/desativar a si mesmo nem o último admin ativo.

## Testes

A matriz de permissões completa é testada em `tests/test_rbac.py`:

- `test_rbac_matrix` — tabela paramétrica com 18 casos (cada combinação de método/endpoint/role).
- `test_admin_cannot_demote_self` — auto-rebaixamento bloqueado.
- `test_admin_cannot_remove_last_active_admin` — defesa contra último admin (via `monkeypatch` no contador, já que o cenário real é inalcançável via HTTP normal).
- `test_admin_can_change_role` / `test_admin_can_deactivate_user` — fluxos positivos.
- `test_admin_role_change_rejects_invalid_role` — validação de payload.
- `test_admin_role_change_404_for_unknown_user` — anti-enumeração.

Para rodar:

```bash
pytest tests/test_rbac.py -v
```

## Referências

- Issue #3: [FEATURE] RBAC: roles admin/analyst/viewer
- Issue #1: [FEATURE] Autenticação JWT + refresh tokens (fundação)
- Issue #13: [FEATURE] Telas de login/registro + proteção do frontend e das APIs
- `openm/core/auth.py` — decorators `require_auth`, `require_role`, `login_required_page`
- `openm/models/user.py` — `User` model + `VALID_ROLES`
- `openm/api/admin.py` — endpoints `/api/admin/*`
- `openm/frontend/static/js/permissions.js` — helper de UI
