# Makefile — OpenM
#
# Modo híbrido de dev:
# - DB e Neo4j rodam via docker compose
# - Flask roda local com hot-reload (outro terminal)
#
# Uso básico:
#   make install        # primeira vez: cria venv + deps
#   make db-up          # sobe postgres + neo4j
#   make api            # roda flask local (precisa do venv ativado)
#   make test           # roda pytest
#   make db-down        # para tudo
#   make create-admin   # cria/promove um admin (requer EMAIL e PASSWORD)
#
# Variáveis úteis (todas opcionais, com defaults):
#   EMAIL=admin@x.com       email do admin a criar/promover
#   PASSWORD='s3nh@F0rte'   senha do admin (≥8 chars)
#   FORCE=1                 promove ao invés de falhar se email já existe
#   ADMIN_VIA=cli|script    estratégia: 'cli' (flask admin create-admin) ou
#                           'script' (scripts/create_admin.py standalone,
#                           ideal para Kame sem venv completo)

PYTHON ?= python3
VENV   ?= venv
PORT   ?= 5000

# Carrega .env.local se existir (modo dev local)
ifneq (,$(wildcard .env.local))
include .env.local
export
endif

.PHONY: help venv install db-up db-down db-logs db-status db-reset \
        api api-shell test test-auth test-api test-issue14 lint debug clean reset \
        create-admin create-admin-cli create-admin-script

help: ## Mostra esta ajuda
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## .*$$/ {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ============ Setup ============

venv: ## Cria virtualenv em ./venv
	$(PYTHON) -m venv $(VENV)
	@echo "✓ Ative com: source $(VENV)/bin/activate"

install: venv ## Cria venv (se necessário) e instala dependências
	. $(VENV)/bin/activate && pip install --upgrade pip && pip install -r requirements.txt
	@echo "✓ Dependências instaladas"

# ============ Banco de dados (Docker) ============

db-up: ## Sobe Postgres + Neo4j (Flask fica local)
	docker compose up -d postgres neo4j
	@echo "✓ Postgres em localhost:5432"
	@echo "✓ Neo4j  em localhost:7474 (browser) / localhost:7687 (bolt)"

db-down: ## Para Postgres + Neo4j
	docker compose down

db-logs: ## Tail dos logs do banco
	docker compose logs -f postgres neo4j

db-status: ## Status dos containers
	docker compose ps

db-reset: db-down ## Para containers e APAGA volumes (DB zerado)
	docker compose down -v
	@echo "✓ Volumes removidos"

# ============ Flask local ============

api: ## Roda Flask local com debug+reload
	. $(VENV)/bin/activate && flask run --debug --host 0.0.0.0 --port $(PORT)

api-shell: ## Abre shell Flask
	. $(VENV)/bin/activate && flask shell

# ============ Testes ============

test: ## Roda pytest suite completa
	. $(VENV)/bin/activate && pytest -v

test-auth: ## Roda só testes de auth
	. $(VENV)/bin/activate && pytest tests/test_auth.py tests/test_auth_pages.py tests/test_auth_protection.py -v

test-api: ## Roda só testes de API
	. $(VENV)/bin/activate && pytest tests/test_api.py tests/test_api_protected.py -v

test-issue14: ## Roda reproducer Playwright da issue #14
	. $(VENV)/bin/activate && python scripts/repro_issue_14.py

# ============ Lint ============

lint: ## flake8 em openm/ e tests/
	. $(VENV)/bin/activate && flake8 openm/ tests/ --max-line-length=120 --extend-ignore=E203,W503

# ============ Admin / Bootstrap ============
#
# Criar o primeiro admin do sistema (issue #3). Necessário em produção
# porque ``ALLOW_REGISTRATION=false`` bloqueia a auto-criação de admins
# via API. Há duas receitas equivalentes:
#
#   make create-admin-cli EMAIL=admin@x.com PASSWORD='senha-forte-123'
#       Usa o comando Flask ``admin create-admin`` (requer venv completo
#       com openm instalado).
#
#   make create-admin-script EMAIL=admin@x.com PASSWORD='senha-forte-123'
#       Usa ``scripts/create_admin.py`` standalone. Funciona sem o venv
#       completo — só precisa de ``psycopg2-binary`` e ``bcrypt``.
#       Ideal para rodar no Kame ou em containers efêmeros.
#
# ``create-admin`` é um wrapper que detecta automaticamente: usa o
# script standalone se disponível (mais resiliente), senão cai pro CLI.
#
# Variáveis:
#   EMAIL     (obrigatório) email do admin
#   PASSWORD  (obrigatório) senha com no mínimo 8 caracteres
#   FORCE=1                 promove usuário existente ao invés de abortar

create-admin: create-admin-script ## Cria/promove admin (auto-detecta CLI ou script)

create-admin-cli: ## Cria admin via Flask CLI (requer venv)
	@if [ -z "$(EMAIL)" ]; then \
		echo "✗ EMAIL não definido. Uso: make create-admin-cli EMAIL=admin@x.com PASSWORD='senha-forte-123'"; \
		exit 2; \
	fi
	@if [ -z "$(PASSWORD)" ]; then \
		echo "✗ PASSWORD não definido. Uso: make create-admin-cli EMAIL=admin@x.com PASSWORD='senha-forte-123'"; \
		exit 2; \
	fi
	. $(VENV)/bin/activate && flask --app openm.app admin create-admin \
		--email '$(EMAIL)' --password '$(PASSWORD)' $(if $(FORCE),--force)

create-admin-script: ## Cria admin via scripts/create_admin.py (standalone, ideal p/ Kame)
	@if [ -z "$(EMAIL)" ]; then \
		echo "✗ EMAIL não definido. Uso: make create-admin-script EMAIL=admin@x.com PASSWORD='senha-forte-123'"; \
		exit 2; \
	fi
	@if [ -z "$(PASSWORD)" ]; then \
		echo "✗ PASSWORD não definido. Uso: make create-admin-script EMAIL=admin@x.com PASSWORD='senha-forte-123'"; \
		exit 2; \
	fi
	@if [ -x "$(VENV)/bin/python" ]; then \
		echo "→ usando Python do venv ($(VENV)/bin/python)"; \
		$(VENV)/bin/python scripts/create_admin.py \
			--email '$(EMAIL)' --password '$(PASSWORD)' $(if $(FORCE),--force) \
			$(if $(strip $(DATABASE_URL)),--database-url '$(DATABASE_URL)',) \
			$(if $(NO_COLOR),--no-color,); \
	else \
		echo "→ venv não encontrado em $(VENV)/ — usando $(PYTHON) do sistema"; \
		echo "  (instale psycopg2-binary e bcrypt para o fallback funcionar)"; \
		$(PYTHON) scripts/create_admin.py \
			--email '$(EMAIL)' --password '$(PASSWORD)' $(if $(FORCE),--force) \
			$(if $(strip $(DATABASE_URL)),--database-url '$(DATABASE_URL)',) \
			$(if $(NO_COLOR),--no-color,); \
	fi

# ============ Debug ============

debug: ## Sobe servidor de debug da issue #14 (Neo4j mockado)
	. $(VENV)/bin/activate && PYTHONPATH=. python scripts/debug_issue_14.py

# ============ Limpeza ============

clean: ## Remove caches python
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ caches removidos"

reset: clean db-reset ## Para tudo, remove caches e volumes
	@echo "✓ ambiente resetado"