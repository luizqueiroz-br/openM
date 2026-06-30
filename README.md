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

# Aplique as migrations (cria as tabelas pela primeira vez)
make db-upgrade
# ou, equivalente: flask --app openm.app db upgrade

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

## 🗄 Migrations de banco (Flask-Migrate / Alembic, issue #36)

A partir da issue #36 o schema do PostgreSQL é gerenciado pelo
[Flask-Migrate](https://flask-migrate.readthedocs.io/) (wrapper de
Alembic). O entrypoint (`entrypoint.sh`) aplica as migrations
automaticamente antes de subir o app.

**Workflow de desenvolvimento:**

```bash
# 1. Suba o Postgres
make db-up

# 2. Aplique as migrations
make db-upgrade

# 3. Depois de alterar models, gere uma nova migration
make db-migrate NAME="add foo column to bar"
# edite migrations/versions/<rev>_add_foo_column_to_bar.py
# (revisar/hand-edit — autogenerate nem sempre acerta tudo)

# 4. Aplique
make db-upgrade
```

**Comandos disponíveis** (todos wrappers de `flask --app openm.app db ...`):

| Alvo | Função |
|---|---|
| `make db-migrate NAME="..."` | Autogenerate de nova migration |
| `make db-upgrade` | Aplica migrations pendentes (idempotente) |
| `make db-downgrade REV=-1` | Reverte UMA migration |
| `make db-stamp REV=head` | Marca o estado sem executar (cutover de DB legado) |
| `make db-history` | Lista o histórico |
| `make db-current` | Mostra a revision atual do banco |

**Cutover de DB legado (primeiro deploy com DB já populado):**

Em produção com dados pré-existentes, rode **uma única vez** após o
primeiro deploy:

```bash
flask db stamp head
```

Isso marca as migrations como aplicadas sem executá-las (equivalente
ao antigo `db.create_all()`). Nas próximas subidas o `flask db upgrade`
no entrypoint detecta o stamp e não faz nada.

**Testes unitários** continuam usando `db.create_all()` / `db.drop_all()`
em SQLite (velocidade + isolamento). Apenas E2E e produção usam
Alembic. Os scripts legados `scripts/migrate_*.sql` foram marcados como
**DEPRECATED** e serão removidos na próxima release.

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

## 🇧🇷 Brasil + Mercado Financeiro + Empresas

A versão `v1.0-brazil` do OpenM adiciona entidades e transforms nativos para fontes públicas brasileiras, com **LGPD Privacy Gate** integrado (opt-in, audit log, export/delete). Tudo roda em modo simulado por padrão — sem chave de API você já consegue testar localmente.

### Quickstart: investigando uma empresa brasileira

1. **Crie uma entidade `Cnpj`**: arraste o card "Cnpj" da paleta (disponível após a release v1.0-brazil) para o canvas → modal com campo "CNPJ (com ou sem pontuação)".
2. **Rode `BrasilApiCnpjTransform`**: clique com botão direito no nó → "Run Transform" → escolhe `brasilapi_cnpj` → o grafo é enriquecido automaticamente com `Estabelecimento`, `Empresa`, `Sócios`, `PessoaFisica`/`PessoaJuridica` e os relacionamentos `IDENTIFICA`, `PARTE_DE`, `SOCIO_DE`, `TEM_PAPEL`.
3. **Cruze com sanções**: clique com botão direito no nó `Empresa` → "Run Transform" → `cgu_sancoes` → nós `Sancao` e `OrgaoSancionador` aparecem se houver ocorrências em CEIS/CNEP/CEPIM.
4. **Cruze com mercado**: se a empresa for listada, rode `cvm_cias_abertas` para confirmar e enriquecer com `CompanhiaAberta` + `Acao` + `setor_b3`. Em seguida, `brapi_quote` traz cotação e fundamentalistas (P/L, P/VP, DY).
5. **Exporte e compartilhe**: "Save" para persistir a investigação; "Download" para JSON.

### Transforms BR planejados (milestone `v1.0-brazil`)

| Transform | Fonte | Autenticação | Cache | Alvo |
|---|---|---|---|---|
| `bacen_sgs` | api.bcb.gov.br (SGS) | nenhuma | 6-24h | Séries macro (Selic, IPCA, CDI, USD) |
| `brasilapi_cep` | brasilapi.com.br | nenhuma | 7d | Endereço + IBGE + coordenadas |
| `brasilapi_cnpj` | brasilapi.com.br | nenhuma | 24h | Empresa + Estabelecimento + QSA |
| `brapi_quote` | brapi.dev | token grátis (15k req/mês) | 30min | Cotações + fundamentalistas + TD |
| `cvm_cias_abertas` | dados.cvm.gov.br | nenhuma | 7d | Companhia aberta + ações |
| `cgu_sancoes` | api.portaldatransparencia.gov.br | API Key (e-mail) | 24h | Sanções (CEIS/CNEP/CEPIM) |

### Novas entidades de grafo

`Cnpj`, `Empresa`, `Estabelecimento`, `Socio`, `PessoaFisica`, `PessoaJuridica`, `Ticker`, `Acao`, `CompanhiaAberta`, `Sancao`, `OrgaoSancionador`, `ProcessoJudicial`, `Movimentacao`, `Municipio`, `MacroSerie`, `IndicadorMacro`.

### LGPD Privacy Gate

- `LGPD_PF_TRANSFORMS_ENABLED` (default `False`): opt-in global para transforms de PF. Sem essa flag, transforms que tocam CPF retornam `403 LGPD_PF_DISABLED`.
- Audit log dedicado (`LGPD_DATA_ACCESS` action) com retenção própria (`LGPD_AUDIT_RETENTION_DAYS`, default 365).
- Endpoints `GET /api/lgpd/export?cpf_mask=...` e `DELETE /api/lgpd/purge?cpf_mask=...` para DSR (art. 18 LGPD).
- Banner no frontend sinaliza investigações com dados pessoais.

### Modo simulado

Defina `OPENM_SIMULATED_BRAZIL=1` no `.env` para usar fixtures locais (`tests/fixtures/brazil/<provider>/*.json`) em vez de chamar a API real. Útil para CI, demos e dev offline.

### Documentação detalhada

- Plano completo de issues: [docs/ISSUES_BRAZIL_OSINT.md](docs/ISSUES_BRAZIL_OSINT.md)
- Milestone no GitHub: <https://github.com/luizqueiroz-br/openM/milestone/5>
- Issues abertas: <https://github.com/luizqueiroz-br/openM/issues?q=is%3Aissue+is%3Aopen+milestone%3Av1.0-brazil>

---

## 🎨 Frontend Redesign

A interface do OpenM está em redesign focado em 4 frentes: **acessibilidade WCAG 2.2 AA**, **responsividade** (mobile/tablet), **produtividade** (mini-map, toasts, command palette) e **visual moderno** (dark/light toggle, Lucide icons, Web Awesome). O redesign preserva a arquitetura vanilla (sem build step, sem React/Vue) e atualiza o Cytoscape de 3.26 → 3.31.

### Marcos planejados

- **`v1.0-frontend "Grafo+"`** — Quick wins: Cytoscape 3.31 + mini-map + export PNG/SVG, sistema de toasts, undo/redo expandido.
- **`v1.0.1-frontend "Tema"`** — Design System com 14 tokens oklch + 8 famílias entity + dark/light toggle. Web Awesome 3.9+ (5 componentes). WCAG 2.2 AA foundations.
- **`v1.1-frontend "OSINT"`** — Inspector 3-tabs (Overview/Properties/Sightings) com Timeline, Transform Hub em árvore (8 categorias), Graph Search & Filter Panel.
- **`v1.1.x-frontend "Mobile"`** — Responsividade em 5 breakpoints (mobile <640 single-col+drawer), Command Palette (Cmd+K).
- **`v1.2-frontend`** — Onboarding tour + 4 templates de investigation (opcional).

### Issues abertas (11)

| # | Issue | Milestone |
|---|---|---|
| [#123](https://github.com/luizqueiroz-br/openM/issues/123) | Canvas upgrade (Cytoscape 3.31 + plugins + export) | v1.0-frontend "Grafo+" |
| [#124](https://github.com/luizqueiroz-br/openM/issues/124) | Sistema de Toasts (Notyf) | v1.0-frontend "Grafo+" |
| [#125](https://github.com/luizqueiroz-br/openM/issues/125) | Undo/Redo expandido (cytoscape-undo-redo) | v1.0-frontend "Grafo+" |
| [#126](https://github.com/luizqueiroz-br/openM/issues/126) | Design System & Theming (CSS tokens + dark/light + oklch) | v1.0.1-frontend "Tema" |
| [#127](https://github.com/luizqueiroz-br/openM/issues/127) | Web Awesome adoption (5 componentes) | v1.0.1-frontend "Tema" |
| [#128](https://github.com/luizqueiroz-br/openM/issues/128) | WCAG 2.2 AA foundations | v1.0.1-frontend "Tema" |
| [#129](https://github.com/luizqueiroz-br/openM/issues/129) | Inspector 3-tabs + Timeline | v1.1-frontend "OSINT" |
| [#130](https://github.com/luizqueiroz-br/openM/issues/130) | Transform Hub em árvore (sidebar tab 2) | v1.1-frontend "OSINT" |
| [#131](https://github.com/luizqueiroz-br/openM/issues/131) | Graph Search & Filter Panel (Fuse.js + checkboxes) | v1.1-frontend "OSINT" |
| [#132](https://github.com/luizqueiroz-br/openM/issues/132) | Responsividade básica (5 breakpoints + drawer mobile) | v1.1.x-frontend "Mobile" |
| [#133](https://github.com/luizqueiroz-br/openM/issues/133) | Command Palette (cmdk-wc, Cmd+K) | v1.1.x-frontend "Mobile" |
| [#134](https://github.com/luizqueiroz-br/openM/issues/134) | Onboarding tour + 4 templates de investigation | v1.2-frontend |

### Decisões-chave

- **Manter Cytoscape.js** (atualizar 3.26 → 3.31.1) e os plugins atuais. NÃO migrar para Sigma.js/G6/Reagraph/react-flow.
- **Adotar Web Awesome 3.9+** como design system (Web Components, MIT, CDN, dark/light nativo, ARIA built-in).
- **Sem build step** (preservar vanilla JS + `window.*`). Nenhuma framework reativa (React/Vue/Svelte).
- **CSS custom properties em `oklch()`** com variantes dark/light via `[data-theme]`.
- **Substituir Font Awesome por Lucide** (1-2 KB inline, melhor estética Maltego-like).

### Documentação detalhada

Plano consolidado: [docs/ISSUES_FRONTEND_REDESIGN.md](docs/ISSUES_FRONTEND_REDESIGN.md)

---

## 🛣️ Roadmap

### ✅ Já entregue

- [x] Autenticação JWT + refresh tokens (issue #1)
- [x] RBAC: admin/analyst/viewer (issue #3)
- [x] Audit log de ações sensíveis com retenção configurável (issue #4)
- [x] Transforms: Whois, GeoIP, Shodan, VirusTotal, DNS records, SSL, MAC OUI, HIBP, Urlscan, AbuseIPDB, crt.sh, SecurityTrails, Hunter, IBAN/SWIFT

### 🚧 Em andamento — milestone [v1.0-brazil](https://github.com/luizqueiroz-br/openM/milestone/5)

- [ ] **#112** Validador e formatador BR (CPF / CNPJ alfanumérico / PIS)
- [ ] **#111** Máscara LGPD + log filter
- [ ] **#113** Entidades de grafo BR (Cnpj, Empresa, Estabelecimento, Socio, PessoaFisica, ...)
- [ ] **#114** Template de issue `brazil-osint.yml`
- [ ] **#115** Transform BACEN SGS Séries Macro
- [ ] **#116** Transform BrasilAPI CEP
- [ ] **#117** Transform BrasilAPI CNPJ
- [ ] **#118** Transform Brapi Cotações + Títulos Públicos
- [ ] **#119** Transform CVM Cadastro Companhias Abertas
- [ ] **#120** Transform Portal da Transparência — Sanções (CEIS/CNEP/CEPIM)
- [ ] **#121** LGPD Privacy Gate (audit + opt-in + banner + data export)

### 🎨 Em planejamento — Frontend Redesign

5 milestones do redesign frontend (issues #123-#134):

- [ ] [`v1.0-frontend "Grafo+"`](https://github.com/luizqueiroz-br/openM/milestone/6) — Cytoscape 3.31 + mini-map + export PNG/SVG, toasts Notyf, undo/redo expandido (#123-#125)
- [ ] [`v1.0.1-frontend "Tema"`](https://github.com/luizqueiroz-br/openM/milestone/7) — Design System oklch + dark/light, Web Awesome, WCAG 2.2 AA (#126-#128)
- [ ] [`v1.1-frontend "OSINT"`](https://github.com/luizqueiroz-br/openM/milestone/8) — Inspector 3-tabs, Transform Hub, Graph Search (#129-#131)
- [ ] [`v1.1.x-frontend "Mobile"`](https://github.com/luizqueiroz-br/openM/milestone/9) — Responsividade + Command Palette (#132-#133)
- [ ] [`v1.2-frontend`](https://github.com/luizqueiroz-br/openM/milestone/10) — Onboarding tour + 4 templates (#134, opcional)

### 🔮 Próximas (v1.1+)

- [ ] Compartilhamento de investigações entre usuários
- [ ] Exportar grafo como PNG/SVG
- [ ] Anotações livres sobre nós
- [ ] Filtros por tipo e propriedade
- [ ] Modo colaborativo em tempo real (WebSocket)
- [ ] Adiados da expansão BR: TSE Candidatos, DataJud CNJ, CoinGecko, Bulk CNPJ, Filtros salvos, Export CSV/XLSX, Heatmap de risco

Para detalhes completos da expansão BR, veja [docs/ISSUES_BRAZIL_OSINT.md](docs/ISSUES_BRAZIL_OSINT.md). Para a matriz de permissões por papel, veja [docs/rbac.md](docs/rbac.md). Para autenticação, veja [docs/auth.md](docs/auth.md).

---

## 📝 Licença

MIT — veja [LICENSE](LICENSE).

---

## ⚠️ Aviso Legal

Use o OpenM apenas em alvos onde você tenha autorização para realizar investigação OSINT. O uso indevido é de responsabilidade do usuário.
