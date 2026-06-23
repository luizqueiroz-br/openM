# OpenM

> Plataforma de investigação visual de vínculos (OSINT/CTI) estilo Maltego, com Flask, Neo4j, PostgreSQL e Cytoscape.js.

![Status](https://img.shields.io/badge/status-MVP-success)
![Stack](https://img.shields.io/badge/stack-Flask%20%7C%20Neo4j%20%7C%20PostgreSQL%20%7C%20Cytoscape.js-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Sobre

O **OpenM** é uma ferramenta open-source para investigação de vínculos em CTI (Cyber Threat Intelligence) e prevenção a fraudes. Permite criar entidades (domínios, IPs, e-mails, pessoas, contas, dispositivos), executar transforms reais (DNS, threat intel) e visualizar a rede de relações em um grafo interativo no estilo Maltego.

## ✨ Features

- **Grafo interativo** com Cytoscape.js (drag, zoom, layout de força)
- **6 tipos de entidades** com ícones distintos (Domain, IPAddress, Email, Person, BankAccount, Device)
- **Transforms reais**:
  - `ResolveIPTransform` — resolução DNS via `socket`
  - `CheckFraudEmailTransform` — EmailRep.io, Have I Been Pwned
- **Drag-and-drop da paleta** para criar nós no canvas
- **Criar arestas manualmente** arrastando de nó a nó (edgehandles)
- **Context menu** (botão direito) com Run Transform, Set Root, Start Link, Delete
- **Inspector** com tabs (Propriedades, Transforms, Adjacentes) e edição inline
- **Undo/Redo** (Ctrl+Z / Ctrl+Y)
- **Export/Import** do grafo como JSON
- **Investigações** persistidas no PostgreSQL
- **Gerenciamento de API Keys** (free/paid) com máscara segura
- **Dark mode** refinado, fontes Inter e JetBrains Mono
- **Atalhos de teclado**: F (fit), Esc (limpar), Delete (remover)

## 📦 Stack

- **Backend**: Python 3.11+ / Flask 3
- **Grafo**: Neo4j 5 Community + driver oficial `neo4j`
- **RDBMS**: PostgreSQL 15 (metadados + API keys)
- **Frontend**: Vanilla JS + Cytoscape.js 3.26
- **Containerização**: Docker + Docker Compose
- **Visualização**: Cytoscape.js com plugins `cose-bilkent`, `cxtmenu`, `edgehandles`

## 🚀 Instalação

### Docker (recomendado)

```bash
git clone https://github.com/<seu-usuario>/openm.git
cd openm
docker compose up --build
```

Acesse:

- **Aplicação**: http://localhost:5000
- **Neo4j Browser**: http://localhost:7474 (neo4j / openm123)
- **PostgreSQL**: localhost:5432 (openm / openm123)

### Local (sem Docker)

```bash
git clone https://github.com/<seu-usuario>/openm.git
cd openm
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure o .env apontando para Neo4j/PostgreSQL locais
cp .env.example .env
# edite NEO4J_URI, DATABASE_URL, etc.

# Crie as tabelas
python -c "from openm.app import create_app; from openm.extensions import db; \
  app = create_app(); ctx = app.app_context(); ctx.push(); db.create_all()"

# Rode
flask run
```

## 🧪 Testes

```bash
source venv/bin/activate
pytest
```

Cobertura atual: 13 testes (entidades, transforms, API).

## 🗂 Estrutura

```text
openm/
├── api/                  # Endpoints REST
├── core/                 # Entity, GraphManager, Transform
├── frontend/             # HTML, CSS, JS
│   ├── static/
│   │   ├── css/         # Dark theme estilo Maltego
│   │   ├── js/          # Módulos JS (graph, inspector, palette, modals)
│   │   └── vendor/      # Cytoscape + plugins (standalone)
│   └── templates/
├── models/              # SQLAlchemy (Investigation, ApiKey)
├── services/            # DNS e Threat Intel
├── transforms/          # ResolveIP, CheckFraudEmail
├── utils/               # Neo4j client singleton
├── tests/
├── config.py
├── extensions.py
└── app.py
```

## 🌐 Endpoints

| Método | Endpoint | Descrição |
|---|---|---|
| POST | `/api/entity` | Criar entidade |
| GET | `/api/transforms/<type>` | Listar transforms |
| POST | `/api/run_transform` | Executar transform |
| GET | `/api/subgraph/<id>?depth=2` | Obter subgrafo |
| POST | `/api/edge` | Criar vínculo manual |
| DELETE | `/api/edge/<id>` | Remover vínculo |
| DELETE | `/api/entity/<id>` | Remover entidade |
| PATCH | `/api/entity/<id>` | Atualizar propriedades |
| GET/POST/DELETE | `/api/investigations` | CRUD investigações |
| GET/POST/DELETE | `/api/keys` | CRUD API keys |
| GET | `/health` | Healthcheck |

## 🔑 Configurando API Keys reais

1. Abra a interface em http://localhost:5000
2. Na sidebar esquerda, aba **API Keys**
3. Selecione o serviço (EmailRep.io, HIBP, AbstractAPI, Shodan)
4. Insira a chave
5. Escolha Free ou Paid
6. Salve — a chave é criptografada e usada pelos transforms

Sem chave, o `CheckFraudEmailTransform` usa simulação controlada.

## 🛣 Roadmap

- [ ] Mais transforms (Whois, GeoIP, Shodan)
- [ ] Autenticação JWT
- [ ] Compartilhamento de investigações entre usuários
- [ ] Exportar grafo como PNG/SVG
- [ ] Anotações livres sobre nós
- [ ] Filtros por tipo e propriedade
- [ ] Modo colaborativo em tempo real (WebSocket)

## 📝 Licença

MIT — veja [LICENSE](LICENSE).

## ⚠️ Aviso Legal

Use o OpenM apenas em alvos onde você tenha autorização para realizar investigação OSINT. O uso indevido é de responsabilidade do usuário.
