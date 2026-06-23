# Makefile — OpenM
#
# Modo híbrido de dev:
# - DB e Neo4j rodam via docker compose
# - Flask roda local com hot-reload (outro terminal)
#
# Uso básico:
#   make install      # primeira vez: cria venv + deps
#   make db-up        # sobe postgres + neo4j
#   make api          # roda flask local (precisa do venv ativado)
#   make test         # roda pytest
#   make db-down      # para tudo
#

PYTHON ?= python3
VENV   ?= venv
PORT   ?= 5000

# Carrega .env.local se existir (modo dev local)
ifneq (,$(wildcard .env.local))
include .env.local
export
endif

.PHONY: help venv install db-up db-down db-logs db-status db-reset \
        api api-shell test test-auth test-api test-issue14 lint debug clean reset

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