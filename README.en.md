# OpenM

> Open-source platform for visual link investigation (OSINT/CTI) in Maltego style, built with Flask, Neo4j, PostgreSQL and Cytoscape.js.

![Status](https://img.shields.io/badge/status-MVP-success)
![Stack](https://img.shields.io/badge/stack-Flask%20%7C%20Neo4j%20%7C%20PostgreSQL%20%7C%20Cytoscape.js-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[Versão em Português](README.md)

---

## 📸 Screenshots

### Empty state
![Empty state](docs/assets/01_empty.png)

### Graph with applied transform
![Transform](docs/assets/03_transform.png)

### Manual edge + Inspector with Transforms
![Manual edge](docs/assets/04_manual_edge.png)

### Context menu (right-click on node)
![Context menu](docs/assets/05_context_menu.png)

### Full graph with multiple transforms
![Full graph](docs/assets/06_full_graph.png)

### Animated demo
![Demo](docs/assets/demo.gif)

---

## ✨ Features

- **Interactive graph** with Cytoscape.js (drag, zoom, cose-bilkent force layout)
- **6 entity types** with distinct icons:
  - 🌐 Domain · 🛜 IPAddress · ✉ Email · 👤 Person · 💳 BankAccount · ▣ Device
- **Real transforms**:
  - `ResolveIPTransform` — DNS resolution via `socket.gethostbyname_ex`
  - `CheckFraudEmailTransform` — EmailRep.io, Have I Been Pwned
- **Drag-and-drop** from palette to canvas creates entities with modal
- **Manually create edges** by dragging from node to node (edgehandles) with type modal
- **Context menu** (right-click): Run Transform, Run All, Set as Root, Start Link, Edit, Copy, Delete
- **Side Inspector** with tabs (Properties, Transforms, Adjacent) and inline editing
- **Undo/Redo** (Ctrl+Z / Ctrl+Y)
- **Export/Import** graph as JSON
- **Investigations** persisted in PostgreSQL
- **API Key management** for free/paid services with secure masking
- **Refined dark mode**, Inter and JetBrains Mono fonts
- **Shortcuts**: F (fit), Esc (clear), Delete (remove)

---

## 📦 Stack

- **Backend**: Python 3.11+ / Flask 3
- **Graph DB**: Neo4j 5 Community + official `neo4j` driver
- **RDBMS**: PostgreSQL 15 (metadata + API keys)
- **Frontend**: Vanilla JS + Cytoscape.js 3.26
- **Containerization**: Docker + Docker Compose

Cytoscape plugins:
- `cytoscape-cose-bilkent@2.0.0` (force layout)
- `cytoscape-edgehandles@3.2.4` (drag-to-connect)
- `cytoscape-cxtmenu@3.4.0` (context menu)

---

## 🚀 Installation

### Docker (recommended)

```bash
git clone https://github.com/luizqueiroz-br/openM.git
cd openM
docker compose up --build
```

Access:

- **Application**: http://localhost:5000
- **Neo4j Browser**: http://localhost:7474 (neo4j / openm123)
- **PostgreSQL**: localhost:5432 (openm / openm123)

### Local (without Docker)

```bash
git clone https://github.com/luizqueiroz-br/openM.git
cd openM
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit NEO4J_URI, DATABASE_URL as needed

# Create tables
python -c "from openm.app import create_app; from openm.extensions import db; \
  app = create_app(); ctx = app.app_context(); ctx.push(); db.create_all()"

flask run
```

---

## 🧪 Tests

```bash
source venv/bin/activate
pytest
```

Coverage: 13 tests (entities, transforms, API).

---

## 🗂 Structure

```text
openm/
├── api/                  # REST endpoints
├── core/                 # Entity, GraphManager, Transform
├── frontend/             # HTML, CSS, JS
│   ├── static/
│   │   ├── css/         # Dark theme Maltego-style
│   │   ├── js/          # JS modules (graph, inspector, palette, modals)
│   │   └── vendor/      # Cytoscape + plugins (standalone)
│   └── templates/
├── models/              # SQLAlchemy (Investigation, ApiKey)
├── services/            # DNS and Threat Intel
├── transforms/          # ResolveIP, CheckFraudEmail
├── utils/               # Neo4j client singleton
├── tests/
├── config.py
├── extensions.py
└── app.py
```

---

## 🌐 Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/entity` | Create entity |
| GET | `/api/transforms/<type>` | List transforms |
| POST | `/api/run_transform` | Run transform |
| GET | `/api/subgraph/<id>?depth=2` | Get subgraph |
| POST | `/api/edge` | Create manual edge |
| DELETE | `/api/edge/<id>` | Remove edge |
| DELETE | `/api/entity/<id>` | Remove entity |
| PATCH | `/api/entity/<id>` | Update properties |
| GET/POST | `/api/investigations` | Investigations CRUD |
| GET/POST/DELETE | `/api/keys` | API keys CRUD |
| GET | `/health` | Healthcheck |

---

## 🔑 Configuring Real API Keys

1. Open the interface at http://localhost:5000
2. In the left sidebar, **API Keys** section
3. Select the service (EmailRep.io, HIBP, AbstractAPI, Shodan)
4. Enter the key
5. Choose Free or Paid
6. Save — the key is stored and used by transforms

Without a registered key, `CheckFraudEmailTransform` uses controlled simulation.

---

## 🎯 How to use

1. **Add an entity**: drag a card from the left palette to the canvas → creation modal appears
2. **Right-click** on a node → menu with Run Transform, Set Root, Start Link, Delete
3. **Create edge**: drag from one node to another (handle) → modal to choose relationship type
4. **Select node**: click → Inspector opens with tabs (Properties, Transforms, Adjacent)
5. **Run transform**: in the Transforms tab, click a button
6. **Save**: "Save" button in the topbar creates an investigation
7. **Export**: "Download" button saves the graph as JSON
8. **Import**: "Upload" button loads a graph from JSON

---

## 🛣 Roadmap

- [ ] More transforms (Whois, GeoIP, Shodan, VirusTotal)
- [ ] JWT authentication
- [ ] Investigation sharing between users
- [ ] Export graph as PNG/SVG
- [ ] Free-form annotations on nodes
- [ ] Filters by type and property
- [ ] Real-time collaborative mode (WebSocket)

---

## 📝 License

MIT — see [LICENSE](LICENSE).

---

## ⚠️ Legal Notice

Only use OpenM on targets where you have authorization to perform OSINT investigation. Misuse is the user's responsibility.
