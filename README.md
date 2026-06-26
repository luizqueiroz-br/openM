# OpenM

> Plataforma open-source de investigação visual de vínculos (OSINT/CTI) estilo Maltego, com Flask, Neo4j, PostgreSQL e Cytoscape.js.

[![CI](https://github.com/luizqueiroz-br/openM/actions/workflows/ci.yml/badge.svg)](https://github.com/luizqueiroz-br/openM/actions/workflows/ci.yml)
![Status](https://img.shields.io/badge/status-MVP-success)
![Stack](https://img.shields.io/badge/stack-Flask%20%7C%20Neo4j%20%7C%20PostgreSQL%20%7C%20Cytoscape.js-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[English version](README.en.md)

---

## 📸 Screenshots

### Estado inicial
![Empty state](docs/assets/01_empty.png)

### Grafo com transform aplicado
![Transform](docs/assets/03_transform.png)

### Edge manual + Inspector com Transforms
![Manual edge](docs/assets/04_manual_edge.png)

### Context menu (botão direito no nó)
![Context menu](docs/assets/05_context_menu.png)

### Grafo completo com múltiplos transforms
![Full graph](docs/assets/06_full_graph.png)

### Demonstração animada
![Demo](docs/assets/demo.gif)

---

## ✨ Funcionalidades

- **Grafo interativo** com Cytoscape.js (drag, zoom, layout de força cose-bilkent)
- **6 tipos de entidades** com ícones distintos:
  - 🌐 Domain · 🛜 IPAddress · ✉ Email · 👤 Person · 💳 BankAccount · ▣ Device
- **Transforms reais**:
  - `ResolveIPTransform` — resolução DNS via `socket.gethostbyname_ex`
  - `CheckFraudEmailTransform` — EmailRep.io, Have I Been Pwned
- **Drag-and-drop da paleta** para o canvas cria entidades com modal
- **Criar arestas manualmente** arrastando de nó a nó (edgehandles) com modal de tipo
- **Context menu** (botão direito): Run Transform, Run All, Set as Root, Start Link, Edit, Copy, Delete
- **Inspector lateral** com tabs (Propriedades, Transforms, Adjacentes) e edição inline
- **Undo/Redo** (Ctrl+Z / Ctrl+Y)
- **Export/Import** do grafo como JSON
- **Investigações** persistidas no PostgreSQL
- **Gerenciamento de API Keys** free/paid com máscara segura
- **Dark mode** refinado, fontes Inter e JetBrains Mono
- **Atalhos**: F (fit), Esc (limpar), Delete (remover)

---

## 📦 Stack

- **Backend**: Python 3.11+ / Flask 3
- **Grafo**: Neo4j 5 Community + driver oficial `neo4j`
- **RDBMS**: PostgreSQL 15 (metadados + API keys)
- **Frontend**: Vanilla JS + Cytoscape.js 3.26
- **Containerização**: Docker + Docker Compose

Plugins Cytoscape:
- `cytoscape-cose-bilkent@2.0.0` (layout de força)
- `cytoscape-edgehandles@3.2.4` (drag-to-connect)
- `cytoscape-cxtmenu@3.4.0` (context menu)

---

## 🚀 Instalação

### Docker (recomendado)

```bash
git clone https://github.com/luizqueiroz-br/openM.git
cd openM
docker compose up --build
```

Acesse:

- **Aplicação**: http://localhost:5000
- **Neo4j Browser**: http://localhost:7474 (neo4j / openm123)
- **PostgreSQL**: localhost:5432 (openm / openm123)

### Local (sem Docker)

```bash
git clone https://github.com/luizqueiroz-br/openM.git
cd openM
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edite NEO4J_URI, DATABASE_URL conforme necessário

# Crie as tabelas
python -c "from openm.app import create_app; from openm.extensions import db; \
  app = create_app(); ctx = app.app_context(); ctx.push(); db.create_all()"

flask run
```

---

## 🧪 Testes

```bash
source venv/bin/activate
pytest
```

Cobertura: 78+ testes (audit log, auth, RBAC, entidades, transforms, API).

### Testes E2E (Neo4j + Postgres reais)

Testes end-to-end que validam o flow completo contra backend real
(Postgres + Neo4j via Docker). Mais lentos e **skipped por padrão**
(marcados com `@pytest.mark.e2e` + `addopts = -m "not e2e"`).

**Setup:**

```bash
make db-up                                   # sobe Postgres + Neo4j
docker compose exec postgres createdb -U openm openm_e2e
```

**Rodar:**

```bash
make test-e2e                                # roda só os E2E (10 testes)
# ou manualmente:
TEST_DATABASE_URL=postgresql://openm:openm123@localhost:5432/openm_e2e \
NEO4J_URI=bolt://localhost:7687 \
NEO4J_USER=neo4j \
NEO4J_PASSWORD=openm123 \
pytest -v -m e2e tests/e2e/
```

O `make test` (sem `-m e2e`) pula esses testes automaticamente — você
não precisa de Docker rodando para o suite de unit/integration.

---

## 🗂 Estrutura

```text
openm/
├── api/                  # Endpoints REST (auth, admin, entities, audit-log...)
├── core/                 # Entity, GraphManager, Transform, audit helpers
├── frontend/             # HTML, CSS, JS
│   ├── static/
│   │   ├── css/         # Dark theme estilo Maltego
│   │   ├── js/          # Módulos JS (graph, inspector, palette, modals)
│   │   └── vendor/      # Cytoscape + plugins (standalone)
│   └── templates/
├── models/              # SQLAlchemy (User, Investigation, ApiKey, AuditLog)
├── services/            # DNS e Threat Intel
├── transforms/          # ResolveIP, CheckFraudEmail
├── utils/               # Neo4j client singleton
├── tests/
├── scripts/             # Migrations SQL
├── config.py
├── extensions.py
└── app.py
```

---

## 🌐 Endpoints

| Método | Endpoint | Descrição |
|---|---|---|
| POST | `/api/auth/register` | Registrar novo usuário |
| POST | `/api/auth/login` | Login (retorna tokens) |
| POST | `/api/auth/logout` | Logout (revoga refresh) |
| POST | `/api/auth/refresh` | Renovar access token |
| GET | `/api/auth/me` | Dados do usuário atual |
| POST | `/api/entity` | Criar entidade |
| PATCH | `/api/entity/<id>` | Atualizar propriedades |
| DELETE | `/api/entity/<id>` | Remover entidade |
| GET | `/api/transforms/<type>` | Listar transforms |
| POST | `/api/run_transform` | Executar transform |
| GET | `/api/subgraph/<id>?depth=2` | Obter subgrafo |
| POST | `/api/edge` | Criar vínculo manual |
| DELETE | `/api/edge/<id>` | Remover vínculo |
| GET/POST | `/api/investigations` | CRUD investigações |
| GET/POST/DELETE | `/api/keys` | CRUD API keys |
| GET | `/api/admin/users` | Listar usuários (admin) |
| PATCH | `/api/admin/users/<id>/role` | Alterar papel (admin) |
| PATCH | `/api/admin/users/<id>/active` | Ativar/desativar (admin) |
| GET | `/api/audit-log` | Log de auditoria (admin) |
| GET | `/health` | Healthcheck |

---

## 📋 Audit log (issue #4)

O OpenM registra automaticamente ações sensíveis em uma tabela `audit_log`:

- Login/logout, criação/edição/remoção de entidades, execução de transforms, alterações de papel, etc.
- Sanitização automática: senhas e tokens nunca são gravados no log.
- Leitura restrita a admins via `GET /api/audit-log` com filtros (`user_id`, `action`, `since`, `until`, etc.).
- Retenção configurável via CLI:

```bash
flask audit purge --days 90        # remove logs antigos
flask audit purge --days 90 --dry-run  # apenas simula
```

## 🔑 Configurando API Keys reais

1. Abra a interface em http://localhost:5000
2. Na sidebar esquerda, aba **API Keys**
3. Selecione o serviço (EmailRep.io, HIBP, AbstractAPI, Shodan)
4. Insira a chave
5. Escolha Free ou Paid
6. Salve — a chave é armazenada e usada pelos transforms

Sem chave cadastrada, o `CheckFraudEmailTransform` usa simulação controlada.

---

## 🎯 Como usar

1. **Adicionar uma entidade**: arraste um card da palette esquerda para o canvas → modal de criação aparece
2. **Botão direito** em um nó → menu com Run Transform, Set Root, Start Link, Delete
3. **Criar vínculo**: arraste de um nó para outro (handle) → modal para escolher tipo de relação
4. **Selecionar nó**: clique → Inspector abre com tabs (Propriedades, Transforms, Adjacentes)
5. **Rodar transform**: na aba Transforms, clique em um botão
6. **Salvar**: botão "Save" na topbar cria uma investigação
7. **Exportar**: botão "Download" salva o grafo em JSON
8. **Importar**: botão "Upload" carrega um grafo de JSON

---

## 🛣 Roadmap

- [x] Autenticação JWT + refresh tokens (issue #1)
- [x] RBAC: admin/analyst/viewer (issue #3)
- [x] Audit log de ações sensíveis com retenção configurável (issue #4)
- [ ] Mais transforms (Whois, GeoIP, Shodan, VirusTotal)
- [ ] Compartilhamento de investigações entre usuários
- [ ] Exportar grafo como PNG/SVG
- [ ] Anotações livres sobre nós
- [ ] Filtros por tipo e propriedade
- [ ] Modo colaborativo em tempo real (WebSocket)

Para detalhes de autenticação, veja [docs/auth.md](docs/auth.md). Para a matriz de permissões por papel, veja [docs/rbac.md](docs/rbac.md).

---

## 📝 Licença

MIT — veja [LICENSE](LICENSE).

---

## ⚠️ Aviso Legal

Use o OpenM apenas em alvos onde você tenha autorização para realizar investigação OSINT. O uso indevido é de responsabilidade do usuário.
