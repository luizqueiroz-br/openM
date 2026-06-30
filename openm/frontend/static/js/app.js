/**
 * App - orquestração principal do OpenM.
 */

/**
 * AutoSave (issue #28) — salva o grafo no backend a cada 2 minutos
 * se houver mudanças (snapshot via PUT /api/investigations/<id>).
 *
 * Lifecycle:
 *   start(id, version)  — começar a observar (chamar ao criar/abrir investigation)
 *                          version = currentInvestigationVersion para If-Match
 *   stop()              — parar (limpar grafo, arquivar, logout)
 *   markDirty()         — marcar como tendo mudanças
 *   tick()              — chamado a cada 2min; se dirty, faz PUT (com If-Match)
 *   render()            — atualiza o indicador #save-status
 *
 * Optimistic locking (issue #37):
 *   - Envia ``If-Match: "<currentInvestigationVersion>"`` em cada PUT
 *   - Em 409 (conflito): abre modal de resolução e PAUSA o auto-save
 *     até o user decidir (Cancelar / Recarregar / Sobrescrever)
 */
const AutoSave = {
    intervalId: null,
    intervalMs: 2 * 60 * 1000,
    currentInvestigationId: null,
    currentInvestigationVersion: null,
    hasChanges: false,
    _saving: false,
    _lastError: null,

    start(investigationId, version = null) {
        this.stop();
        if (!investigationId) return;
        this.currentInvestigationId = investigationId;
        this.currentInvestigationVersion = version;
        this.hasChanges = false;
        this._saving = false;
        this._lastError = null;
        this.intervalId = setInterval(() => this.tick(), this.intervalMs);
        this.render();
    },

    stop() {
        if (this.intervalId !== null) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
        this.currentInvestigationId = null;
        this.currentInvestigationVersion = null;
        this.hasChanges = false;
        this._saving = false;
        this._lastError = null;
        this.render();
    },

    markDirty() {
        if (!this.currentInvestigationId) return;
        this.hasChanges = true;
        this.render();
    },

    async tick() {
        if (!this.hasChanges || !this.currentInvestigationId || this._saving) return;
        this._saving = true;
        this.render();

        try {
            const snapshot = Graph.exportJson();
            const cleanSnapshot = {
                nodes: snapshot.nodes || [],
                edges: snapshot.edges || [],
            };
            const response = await OpenMAPI.updateInvestigation(
                this.currentInvestigationId,
                { graph_snapshot: cleanSnapshot },
                { ifMatch: this.currentInvestigationVersion },
            );
            // Sucesso: atualiza version local para o próximo tick
            if (response && response.investigation && response.investigation.version) {
                this.currentInvestigationVersion = response.investigation.version;
            }
            this.hasChanges = false;
            this._lastError = null;
        } catch (err) {
            if (err.status === 404) {
                // Investigation sumiu (deletada em outra aba) — issue #35
                console.warn('Auto-save: investigation não encontrada (404). Parando.');
                this.stop();
                if (window.Graph && window.Graph.clear) window.Graph.clear();
                if (window.App && window.App.setStatus) {
                    window.App.setStatus(
                        'Investigação não encontrada (provavelmente excluída). Auto-save parado.',
                        'warning',
                    );
                }
                return;
            }
            if (err.status === 409) {
                // Conflito de versão (issue #37) — abre modal de resolução
                console.warn('Auto-save: conflito de versão (409). Abrindo modal.');
                const conflictData = err.body || {};
                this._handleConflict(conflictData);
                return;
            }
            // Outros erros: comportamento legado (retry no próximo tick)
            this._lastError = err.message || 'erro desconhecido';
            console.error('Auto-save falhou:', err);
        } finally {
            this._saving = false;
            this.render();
        }
    },

    /**
     * Trata 409 Conflict vindo do PUT (issue #37).
     *
     * Abre Modal.conflictResolve com 3 opções:
     *   - Cancelar:    mantém grafo local, marca como não salvo
     *   - Recarregar:  substitui grafo com current_snapshot do servidor
     *   - Sobrescrever: PUT sem If-Match (força; descarta versão do servidor)
     */
    _handleConflict(conflictData) {
        // Marca hasChanges=false para parar de tentar save até o user decidir.
        this.hasChanges = false;
        this._lastError = 'conflito';

        if (window.Modal && window.Modal.conflictResolve) {
            window.Modal.conflictResolve({
                currentVersion: conflictData.current_version,
                yourVersion: conflictData.your_version,
                currentSnapshot: conflictData.current_snapshot,
                onReload: () => {
                    // Recarrega: substitui grafo + atualiza version local.
                    if (conflictData.current_snapshot) {
                        Graph.loadSnapshot(conflictData.current_snapshot);
                    }
                    this.currentInvestigationVersion = conflictData.current_version;
                    this._lastError = null;
                    if (window.App && window.App.setStatus) {
                        window.App.setStatus(
                            'Snapshot recarregado do servidor. Suas alterações locais foram perdidas.',
                            'warning',
                        );
                    }
                    this.render();
                },
                onOverwrite: async () => {
                    // Sobrescreve: PUT sem If-Match (servidor não checa).
                    this._lastError = null;
                    this.render();
                    try {
                        const snapshot = Graph.exportJson();
                        const cleanSnapshot = {
                            nodes: snapshot.nodes || [],
                            edges: snapshot.edges || [],
                        };
                        const response = await OpenMAPI.updateInvestigation(
                            this.currentInvestigationId,
                            { graph_snapshot: cleanSnapshot },
                            // SEM ifMatch — sobrescreve sem check.
                        );
                        if (response && response.investigation && response.investigation.version) {
                            this.currentInvestigationVersion = response.investigation.version;
                        }
                        this.hasChanges = false;
                        if (window.App && window.App.setStatus) {
                            window.App.setStatus(
                                'Versão do servidor sobrescrita.',
                                'success',
                            );
                        }
                    } catch (e) {
                        this._lastError = e.message || 'erro ao sobrescrever';
                        if (window.App && window.App.setStatus) {
                            window.App.setStatus(
                                `Erro ao sobrescrever: ${e.message}`,
                                'error',
                            );
                        }
                    } finally {
                        this.render();
                    }
                },
                onCancel: () => {
                    // Cancela: mantém grafo local, marca como não salvo.
                    this.hasChanges = true;
                    this._lastError = 'conflito';
                    if (window.App && window.App.setStatus) {
                        window.App.setStatus(
                            'Conflito não resolvido. Salve manualmente após revisar.',
                            'warning',
                        );
                    }
                    this.render();
                },
            });
        } else {
            // Fallback se Modal.conflictResolve não existir (dev/test)
            console.error('Modal.conflictResolve não disponível');
            alert('Conflito de versão detectado. Recarregue a página.');
        }
    },

    render() {
        const el = document.getElementById('save-status');
        if (!el) return;

        if (!this.currentInvestigationId) {
            el.textContent = '—';
            el.className = '';
            return;
        }
        if (this._saving) {
            el.textContent = '⏳ Salvando...';
            el.className = 'saving';
            return;
        }
        if (this._lastError) {
            el.textContent = `✗ ${this._lastError}`;
            el.className = 'error';
            return;
        }
        if (this.hasChanges) {
            el.textContent = '● Não salvo';
            el.className = 'dirty';
            return;
        }
        el.textContent = '✓ Salvo';
        el.className = 'saved';
    },
};
window.AutoSave = AutoSave;

const App = {
    setStatus(message, type = 'info') {
        const el = document.getElementById('status-msg');
        if (el) el.textContent = message;
        let color = 'var(--text-dim)';
        if (type === 'error') color = 'var(--danger)';
        else if (type === 'success') color = 'var(--success)';
        // Issue #128: warning era silenciosamente text-dim — agora tem cor própria
        else if (type === 'warning') color = 'var(--warn)';
        if (el) el.style.color = color;

        // Issue #128: announce para screen readers
        // Polite para success/info, assertive para error/warning
        if (message) {
            const priority = (type === 'error' || type === 'warning') ? 'assertive' : 'polite';
            this.announce(message, priority);
        }
    },

    // ─────────────────────────────────────────────────────────────────────
    // Accessibility (issue #128 — WCAG 2.2 AA foundations)
    // Anuncia mensagens para screen readers via aria-live regions.
    // As 2 regions já existem nos templates (Lane 2): #sr-status (polite)
    // e #sr-alert (assertive). polite = success/info, assertive = error/warning.
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Announce a message to screen readers via aria-live regions.
     * @param {string} message — the text to announce
     * @param {'polite'|'assertive'} priority — defaults to 'polite'
     */
    announce(message, priority = 'polite') {
        if (!message) return;
        const id = priority === 'assertive' ? 'sr-alert' : 'sr-status';
        const region = document.getElementById(id);
        if (!region) {
            console.warn('openm: aria-live region not found:', id);
            return;
        }
        // Limpa primeiro para garantir que screen readers re-anunciam mensagens idênticas
        region.textContent = '';
        // Pequeno delay para screen readers detectarem a mudança
        setTimeout(() => { region.textContent = message; }, 50);
    },

    /**
     * Switch active sidebar tab (Entities / Investigations / Transforms / Admin).
     * Triggers a focus shift for keyboard users.
     * @param {1|2|3|4} n — tab number
     */
    switchSidebarTab(n) {
        const tabs = ['entities', 'investigations', 'transforms', 'admin'];
        if (n < 1 || n > tabs.length) return;
        const tab = tabs[n - 1];
        this.setActiveSidebarTab(tab);
    },

    /**
     * Ativa a tab da sidebar (e esconde as outras).
     * Issue #130: gerencia o estado das 4 tabs (entities/investigations/transforms/admin).
     * @param {'entities'|'investigations'|'transforms'|'admin'} name
     */
    setActiveSidebarTab(name) {
        // Esconde todas as sections, mostra a ativa
        document.querySelectorAll('.sidebar-section[id^="section-"]').forEach((s) => {
            s.hidden = s.id !== `section-${name}`;
        });
        // Atualiza aria-selected e tabindex dos tabs
        document.querySelectorAll('.sidebar-tab').forEach((t) => {
            const isActive = t.dataset.tab === name;
            t.setAttribute('aria-selected', isActive ? 'true' : 'false');
            t.setAttribute('tabindex', isActive ? '0' : '-1');
            t.classList.toggle('active', isActive);
        });
        // Aplica RBAC gate (esconde sections restritas para o role atual)
        if (window.OpenMPermissions && typeof window.OpenMPermissions.applyRoleGates === 'function') {
            window.OpenMPermissions.applyRoleGates(this.currentUser);
        }
        if (typeof this.announce === 'function') {
            this.announce(`Aba ${name} ativada`, 'polite');
        }
    },

    // ─────────────────────────────────────────────────────────────────────
    // Theme management (issue #126 — Design System & Theming)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Apply stored theme from localStorage (or system preference on first visit).
     * Called once during App.init() before bindTopbar().
     * Sets data-theme attribute on <html> and updates the toggle button icon.
     */
    applyStoredTheme() {
        const stored = localStorage.getItem('openm.theme');
        const prefersLight = window.matchMedia &&
            window.matchMedia('(prefers-color-scheme: light)').matches;
        const theme = stored || (prefersLight ? 'light' : 'dark');
        this.setTheme(theme, /* persist */ false);
    },

    // ─────────────────────────────────────────────────────────────────────
    // Responsive helpers (issue #132 — Lane 3 / JS)
    // Centraliza a detecção de viewport para todas as decisões de layout.
    // Breakpoints: tablet <=1024, mobile <=768 (alinhados com style.css).
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @returns {boolean} true se a viewport é mobile (max-width 768px).
     * Usado para decidir se elementos `.mobile-only` devem ser exibidos
     * e se o canvas deve caber na tela sem scroll lateral.
     */
    _isMobile() {
        return window.matchMedia('(max-width: 768px)').matches;
    },

    /**
     * @param {Element|null} el
     * @returns {boolean} true se o elemento recebe texto digitado pelo
     * usuário (input, textarea, select, contenteditable). Usado para
     * gatear atalhos de tecla única (ex: '?', 'F') que não devem
     * disparar quando o usuário está digitando em um campo.
     */
    _isEditable(el) {
        if (!el) return false;
        const tag = el.tagName;
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
    },

    /**
     * @returns {boolean} true se a viewport é tablet ou menor (max-width 1024px).
     * Usado para decidir se as sidebars devem virar drawers (overlays
     * deslizantes) e se atalhos de toggle (Cmd+B / Cmd+I) devem usar a
     * lógica mobile-first.
     */
    _isTablet() {
        return window.matchMedia('(max-width: 1024px)').matches;
    },

    /**
     * Set the active theme.
     * @param {'dark'|'light'} theme
     * @param {boolean} persist — whether to write to localStorage
     */
    setTheme(theme, persist = true) {
        const html = document.documentElement;
        if (theme === 'light') {
            html.setAttribute('data-theme', 'light');
        } else {
            html.removeAttribute('data-theme');
        }
        // Update the toggle button icon (moon for light→dark action, sun for dark→light)
        const icon = document.getElementById('theme-icon');
        if (icon) {
            // fa-moon = "switch to dark" (current is light); fa-sun = "switch to light" (current is dark)
            icon.className = theme === 'light' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
        }
        // Update aria-label for screen readers
        const btn = document.getElementById('btn-theme');
        if (btn) {
            btn.setAttribute('aria-label',
                theme === 'light' ? 'Mudar para tema escuro' : 'Mudar para tema claro');
            btn.setAttribute('title',
                theme === 'light' ? 'Tema escuro (Ctrl+Shift+T)' : 'Tema claro (Ctrl+Shift+T)');
        }
        if (persist) {
            try {
                localStorage.setItem('openm.theme', theme);
            } catch (e) {
                // localStorage may be unavailable (private mode, etc.) — silently ignore
                console.warn('openm: localStorage unavailable, theme not persisted');
            }
        }
        // Announce to screen reader users
        if (typeof this.announce === 'function') {
            this.announce(`Tema ${theme === 'light' ? 'claro' : 'escuro'} ativado`, 'polite');
        }
    },

    /**
     * Toggle between dark and light themes.
     * Called from the topbar button click handler and the Ctrl+Shift+T shortcut.
     */
    toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'light' ? 'dark' : 'light';
        this.setTheme(next, /* persist */ true);
    },

    // ─────────────────────────────────────────────────────────────────────
    // Responsive drawers (issue #132 — Lane 3 / JS)
    // Em <=1024px, as sidebars (`#palette` e `#inspector`) saem do grid
    // CSS e viram drawers deslizantes com overlay. Em desktop, o CSS
    // já as mantém no grid — `toggleSidebar`/`toggleInspector` apenas
    // sincronizam aria-hidden e estado interno (idempotente).
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Abre/fecha a sidebar esquerda (#palette) como drawer mobile.
     * @param {boolean} [forceState] — true abre, false fecha, undefined alterna.
     */
    toggleSidebar(forceState) {
        const sidebar = document.getElementById('palette');
        const overlay = document.getElementById('sidebar-overlay');
        if (!sidebar) return;
        const isOpen = sidebar.classList.contains('open');
        const nextState = (typeof forceState === 'boolean') ? forceState : !isOpen;

        // Sincroniza classes: .open controla a transição CSS (transform).
        // A classe .sidebar-drawer só é adicionada em <=1024px; em desktop
        // ela forçaria position:fixed e quebraria o grid layout. Por isso,
        // mantemos o estado real do drawer sincronizado com .open apenas.
        sidebar.classList.toggle('open', nextState);

        if (this._isTablet()) {
            // Em tablet/mobile: overlay + aria-hidden no canvas + classe drawer
            sidebar.classList.add('sidebar-drawer');
            if (overlay) overlay.classList.toggle('show', nextState);
            const canvas = document.getElementById('canvas');
            if (canvas) canvas.setAttribute('aria-hidden', nextState ? 'true' : 'false');
        } else {
            // Em desktop: garante que o drawer não tem classe/transform residuais
            // (ex: usuário rotacionou o device de tablet para desktop).
            sidebar.classList.remove('sidebar-drawer');
            if (overlay) overlay.classList.remove('show');
            const canvas = document.getElementById('canvas');
            if (canvas) canvas.removeAttribute('aria-hidden');
        }

        // Atualiza aria-expanded/title do botão hamburger (id #btn-hamburger)
        const hamburger = document.getElementById('btn-hamburger');
        if (hamburger) {
            hamburger.setAttribute('aria-expanded', nextState ? 'true' : 'false');
            hamburger.setAttribute('title', nextState ? 'Fechar sidebar (Cmd+B)' : 'Abrir sidebar (Cmd+B)');
        }

        // cy.resize() após a transição CSS (250ms) para recalcular viewport
        // do Cytoscape. Sem isso, o canvas pode ficar com tamanho errado
        // até a próxima interação.
        if (typeof cy !== 'undefined' && cy) {
            setTimeout(() => { try { cy.resize(); } catch (e) { /* cy disposed */ } }, 250);
        }

        // Move foco para o primeiro elemento focável dentro do drawer
        // (skip-link não conta) — UX keyboard-first em mobile.
        if (nextState) {
            setTimeout(() => {
                const focusable = sidebar.querySelector(
                    'input, button, select, textarea, [tabindex]:not([tabindex="-1"])',
                );
                if (focusable) focusable.focus();
            }, 260);
        }

        // Anúncio para screen readers (issue #128 — WCAG aria-live)
        this.announce(nextState ? 'Sidebar aberta' : 'Sidebar fechada', 'polite');
    },

    /**
     * Abre/fecha o inspector direito (#inspector) como drawer mobile.
     * Paralelo a toggleSidebar — mesma lógica, alvo diferente.
     * @param {boolean} [forceState] — true abre, false fecha, undefined alterna.
     */
    toggleInspector(forceState) {
        const inspector = document.getElementById('inspector');
        const overlay = document.getElementById('inspector-overlay');
        if (!inspector) return;
        const isOpen = inspector.classList.contains('open');
        const nextState = (typeof forceState === 'boolean') ? forceState : !isOpen;

        inspector.classList.toggle('open', nextState);

        if (this._isTablet()) {
            inspector.classList.add('sidebar-drawer-right');
            if (overlay) overlay.classList.toggle('show', nextState);
            const canvas = document.getElementById('canvas');
            if (canvas) canvas.setAttribute('aria-hidden', nextState ? 'true' : 'false');
        } else {
            inspector.classList.remove('sidebar-drawer-right');
            if (overlay) overlay.classList.remove('show');
            const canvas = document.getElementById('canvas');
            if (canvas) canvas.removeAttribute('aria-hidden');
        }

        // Atualiza aria-pressed/title do botão inspector (#btn-toggle-inspector)
        const btn = document.getElementById('btn-toggle-inspector');
        if (btn) {
            btn.setAttribute('aria-pressed', nextState ? 'true' : 'false');
            btn.setAttribute('aria-expanded', nextState ? 'true' : 'false');
            btn.setAttribute('title', nextState ? 'Fechar inspector (Cmd+I)' : 'Alternar inspector (Cmd+I)');
        }

        if (typeof cy !== 'undefined' && cy) {
            setTimeout(() => { try { cy.resize(); } catch (e) { /* cy disposed */ } }, 250);
        }

        if (nextState) {
            setTimeout(() => {
                const focusable = inspector.querySelector(
                    'input, button, select, textarea, [tabindex]:not([tabindex="-1"])',
                );
                if (focusable) focusable.focus();
            }, 260);
        }

        this.announce(nextState ? 'Inspector aberto' : 'Inspector fechado', 'polite');
    },

    /**
     * Fecha ambos os drawers (sidebar + inspector).
     * Usado pelo ESC, por clique no overlay, e pelo listener de resize
     * quando o viewport volta para desktop (evita drawer "preso" aberto
     * após rotação de tablet).
     */
    closeAllDrawers() {
        this.toggleSidebar(false);
        this.toggleInspector(false);
    },

    /**
     * Bridge: react to system theme changes when user has NOT explicitly chosen.
     * If localStorage has a value, the user's explicit choice wins.
     * If not, follow the system.
     */
    watchSystemTheme() {
        if (!window.matchMedia) return;
        const mq = window.matchMedia('(prefers-color-scheme: light)');
        // Modern API
        if (mq.addEventListener) {
            mq.addEventListener('change', (e) => {
                const stored = localStorage.getItem('openm.theme');
                if (!stored) {
                    this.setTheme(e.matches ? 'light' : 'dark', false);
                }
            });
        } else if (mq.addListener) {
            // Legacy Safari < 14
            mq.addListener((e) => {
                const stored = localStorage.getItem('openm.theme');
                if (!stored) {
                    this.setTheme(e.matches ? 'light' : 'dark', false);
                }
            });
        }
    },

    async createEntity(type, value, options = {}) {
        try {
            const data = await OpenMAPI.createEntity(type, value);
            const nodeData = {
                id: data.entity.id,
                label: data.entity.value,
                type: data.entity.type,
                ...data.entity.properties,
            };
            const node = Graph.addNode(nodeData, options.position || (options.x && options.y ? { x: options.x, y: options.y } : null));
            this.setStatus(`Entidade ${type} "${value}" criada.`, 'success');
            return node;
        } catch (err) {
            this.setStatus(err.message, 'error');
            throw err;
        }
    },

    async runTransform(node, transformName) {
        this.setStatus(`Executando ${transformName}...`);
        try {
            const result = await OpenMAPI.runTransform(
                node.id,
                transformName,
                node.type,
                node.label || node.value,
                { ...node },
            );

            const newNodes = (result.entities || []).map(e => {
                const data = { id: e.id, label: e.value, type: e.type };
                for (const [k, v] of Object.entries(e.properties || {})) {
                    if (!['id', 'label', 'type'].includes(k)) {
                        data[k] = v;
                    }
                }
                return { data };
            });

            const newEdges = (result.relationships || []).map(r => {
                const data = {
                    id: r.id || `edge-${r.from_id}-${r.to_id}-${r.type}-${Date.now()}-${Math.random()}`,
                    source: r.from_id,
                    target: r.to_id,
                    label: r.type,
                };
                // Adiciona properties extras sem sobrescrever chaves reservadas
                for (const [k, v] of Object.entries(r.properties || {})) {
                    if (!['id', 'source', 'target', 'label'].includes(k)) {
                        data[k] = v;
                    }
                }
                return { data };
            });

            Graph.addElements({ nodes: newNodes, edges: newEdges });
            this.setStatus(
                `Transform concluído: +${newNodes.length} entidades, +${newEdges.length} vínculos.`,
                'success',
            );
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async runAllTransforms(node) {
        try {
            const data = await OpenMAPI.listTransforms(node.type);
            for (const t of data.transforms) {
                await this.runTransform(node, t.name);
            }
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async updateNodeProperties(id, newProps) {
        try {
            // Usa OpenMAPI.updateEntity em vez de fetch direto pra que o
            // interceptador global dispare refresh automático em 401
            // (issue #17).
            await OpenMAPI.updateEntity(id, newProps);
            // Atualiza no grafo
            const node = cy.getElementById(id);
            if (node.length) {
                node.data(newProps);
            }
            this.setStatus('Propriedades atualizadas.', 'success');
            Inspector.showNode(node.data());
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async deleteNode(id) {
        try {
            await OpenMAPI.deleteEntity(id);
            Graph.removeNode(id);
            this.setStatus('Entidade removida.', 'success');
            Inspector.showEmpty();
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async deleteEdge(id) {
        try {
            await OpenMAPI.deleteEdge(id);
            Graph.removeEdge(id);
            this.setStatus('Vínculo removido.', 'success');
            Inspector.showEmpty();
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async loadInvestigations() {
        try {
            // Lê filtros da UI
            const status = document.getElementById('inv-status-filter')?.value || 'active';
            const sort = document.getElementById('inv-sort')?.value || '-updated_at';
            const search = document.getElementById('inv-search')?.value.trim() || '';

            const data = await OpenMAPI.listInvestigations({ status, sort, search });
            const list = document.getElementById('investigations-list');
            if (!list) return;

            if (!data.investigations || data.investigations.length === 0) {
                const emptyMsg = search
                    ? `Nenhuma investigação encontrada para "${escapeHtml(search)}"`
                    : status === 'archived'
                        ? 'Nenhuma investigação arquivada'
                        : 'Nenhuma investigação';
                list.innerHTML = `<li class="empty">${emptyMsg}</li>`;
                return;
            }

            list.innerHTML = data.investigations.map(inv => {
                const isArchived = inv.status === 'archived';
                const date = inv.updated_at || inv.created_at;
                const isCurrent = AutoSave.currentInvestigationId === inv.id;
                return `
                    <li class="inv-item ${isArchived ? 'archived' : ''} ${isCurrent ? 'current' : ''}"
                        data-id="${inv.id}" data-archived="${isArchived}">
                        <span class="status-dot"></span>
                        <span class="title">${escapeHtml(inv.title)}</span>
                        <span class="meta">${date ? new Date(date).toLocaleDateString() : ''}</span>
                        <div class="inv-actions">
                            <button class="js-open" title="Abrir">
                                <i class="fa-solid fa-folder-open"></i>
                            </button>
                            <button class="js-toggle-archive" title="${isArchived ? 'Desarquivar' : 'Arquivar'}">
                                <i class="fa-solid ${isArchived ? 'fa-box-open' : 'fa-box-archive'}"></i>
                            </button>
                            <button class="js-delete danger" title="Excluir">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </div>
                    </li>`;
            }).join('');

            // Event delegation: cada botão executa sua ação
            list.querySelectorAll('li.inv-item').forEach(li => {
                const id = parseInt(li.dataset.id, 10);
                const isArchived = li.dataset.archived === 'true';

                li.querySelector('.js-open')?.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    await this.openInvestigation(id);
                });

                li.querySelector('.js-toggle-archive')?.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    try {
                        if (isArchived) {
                            await OpenMAPI.unarchiveInvestigation(id);
                            this.setStatus('Investigação desarquivada.', 'success');
                        } else {
                            await OpenMAPI.archiveInvestigation(id);
                            this.setStatus('Investigação arquivada.', 'success');
                            // Se era a investigation aberta, para auto-save
                            if (AutoSave.currentInvestigationId === id) {
                                AutoSave.stop();
                            }
                        }
                        this.loadInvestigations();
                    } catch (err) {
                        this.setStatus(err.message, 'error');
                    }
                });

                li.querySelector('.js-delete')?.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const title = li.querySelector('.title')?.textContent || '';
                    Modal.confirm({
                        title: 'Excluir investigação?',
                        message: `Excluir "${title}"? Esta ação não pode ser desfeita.`,
                        danger: true,
                        onConfirm: () => this.deleteInvestigation(id),
                    });
                });

                // Click no item (não nos botões) também abre
                li.addEventListener('click', () => this.openInvestigation(id));
            });
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    /**
     * DELETE hard da investigation (issue #35).
     * Modal.confirm já pediu confirmação antes de chamar este método.
     *
     * - Se era a investigation aberta: para AutoSave + limpa grafo
     *   (evita loop do AutoSave tentando salvar em um registro que
     *   não existe mais — AutoSave.tick também reage a 404 como rede
     *   de segurança, mas aqui pegamos o caso antes do próximo tick).
     * - Recarrega a lista (o item some).
     * - Em 404: outro user/aba deletou antes — só atualiza lista.
     */
    async deleteInvestigation(id) {
        try {
            await OpenMAPI.deleteInvestigation(id);
        } catch (err) {
            if (err.status === 404) {
                this.setStatus('Investigação não encontrada.', 'error');
                await this.loadInvestigations();
                return;
            }
            this.setStatus(`Erro ao excluir: ${err.message}`, 'error');
            return;
        }
        this.setStatus('Investigação excluída.', 'success');

        // Se era a investigation aberta, parar auto-save + limpar grafo.
        if (AutoSave.currentInvestigationId === id) {
            AutoSave.stop();
            Graph.clear();
        }

        await this.loadInvestigations();
    },

    /**
     * Abre uma investigation: salva a atual (se houver mudanças), busca o
     * snapshot do PG e carrega no grafo. Inicia auto-save com a versão
     * atual (issue #27 + #37).
     */
    async openInvestigation(id) {
        // Salva a investigation atual antes de trocar (se houver mudanças)
        if (AutoSave.currentInvestigationId && AutoSave.currentInvestigationId !== id && AutoSave.hasChanges) {
            this.setStatus('Salvando investigation atual antes de trocar...', 'info');
            await AutoSave.tick();
        }

        try {
            const data = await OpenMAPI.getInvestigation(id);
            const inv = data.investigation;

            // Carrega snapshot no Graph (com fallback se for legacy/null)
            Graph.loadSnapshot(inv.graph_snapshot);

            // Issue #131: notifica o painel de busca/filtro para que possa
            // restaurar o estado persistido (search, types ocultos, vizinhança)
            // do localStorage keyed by investigation id.
            if (window.SearchPanel && typeof window.SearchPanel.setInvestigationId === 'function') {
                window.SearchPanel.setInvestigationId(id);
            }

            // Inicia auto-save com a versão atual (issue #37 — If-Match
            // começa a partir desta versão)
            AutoSave.start(id, inv.version);

            this.setStatus(`Investigação "${inv.title}" carregada.`, 'success');
            this.loadInvestigations();  // atualiza "current" marker
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    /**
     * Salva a investigation atual (se houver uma aberta) ou cria uma nova.
     * Chamado pelo botão Salvar (btn-save) e pelo atalho de teclado.
     */
    async saveInvestigation() {
        // Se tem uma investigation aberta, salva nela
        if (AutoSave.currentInvestigationId) {
            try {
                this.setStatus('Salvando...', 'info');
                await AutoSave.tick();
                this.setStatus('✓ Investigation salva.', 'success');
            } catch (err) {
                this.setStatus(err.message, 'error');
            }
            return;
        }

        // Senão, cria uma nova
        await this.createInvestigation();
    },

    async createInvestigation() {
        const title = document.getElementById('inv-title').value.trim();
        const desc = document.getElementById('inv-desc').value.trim();
        if (!title) {
            this.setStatus('Título é obrigatório', 'error');
            return;
        }
        try {
            const result = await OpenMAPI.createInvestigation(title, desc, null);
            const savedTitle = result?.investigation?.title || title;
            const savedId = result?.investigation?.id;

            // Salva o snapshot atual do grafo na nova investigation.
            // Pega a version retornada pelo PUT pra passar pro AutoSave
            // (issue #37 — start com versão correta evita 409 imediato).
            if (savedId) {
                const snapshot = Graph.exportJson();
                const cleanSnapshot = {
                    nodes: snapshot.nodes || [],
                    edges: snapshot.edges || [],
                };
                const putResult = await OpenMAPI.updateInvestigation(
                    savedId,
                    { graph_snapshot: cleanSnapshot },
                );
                const initialVersion = (putResult && putResult.investigation && putResult.investigation.version) || 1;
                AutoSave.start(savedId, initialVersion);
            }

            this.setStatus(`✓ Investigação "${savedTitle}" criada e salva.`, 'success');
            document.getElementById('inv-title').value = '';
            document.getElementById('inv-desc').value = '';
            this.loadInvestigations();
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async loadKeyServices() {
        try {
            const data = await OpenMAPI.listKeyServices();
            const select = document.getElementById('key-service');
            if (!select) {
                return; // elemento nao presente nesta pagina
            }
            if (!data.services || data.services.length === 0) {
                select.innerHTML = '<option value="">Nenhum serviço disponível</option>';
                return;
            }
            select.innerHTML = data.services.map(s =>
                `<option value="${s.service_name}">${s.display_name}</option>`
            ).join('');
        } catch (err) {
            console.error('Falha ao carregar services:', err);
            const select = document.getElementById('key-service');
            if (select) {
                select.innerHTML = '<option value="">Erro ao carregar</option>';
            }
        }
    },

    async loadKeys() {
        try {
            const data = await OpenMAPI.listKeys();
            const list = document.getElementById('keys-list');
            if (data.keys.length === 0) {
                list.innerHTML = '<li class="empty">Nenhuma chave</li>';
                return;
            }
            list.innerHTML = data.keys.map(k => `
                <li data-id="${k.id}">
                    <span class="title">
                        ${k.service_name} <span class="tag ${k.key_type}">${k.key_type}</span>
                    </span>
                    <span class="meta">${k.masked_key}</span>
                </li>
            `).join('');
            list.querySelectorAll('li').forEach(li => {
                if (!li.classList.contains('empty')) {
                    const id = li.dataset.id;
                    li.addEventListener('click', async () => {
                        if (confirm(`Remover chave ${id}?`)) {
                            await OpenMAPI.deleteKey(id);
                            this.loadKeys();
                            this.setStatus('Chave removida.', 'success');
                        }
                    });
                }
            });
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async saveKey() {
        const service = document.getElementById('key-service').value;
        const value = document.getElementById('key-value').value.trim();
        const type = document.getElementById('key-type').value;
        if (!value) {
            this.setStatus('Chave é obrigatória', 'error');
            return;
        }
        try {
            await OpenMAPI.saveKey(service, value, type);
            this.setStatus(`Chave ${service} salva.`, 'success');
            document.getElementById('key-value').value = '';
            this.loadKeys();
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    exportGraph() {
        const data = Graph.exportJson();
        if (!data) return;
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `openm-graph-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        this.setStatus('Grafo exportado.', 'success');
    },

    importGraph() {
        const input = document.getElementById('file-input');
        input.click();
        input.onchange = (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = () => {
                try {
                    const data = JSON.parse(reader.result);
                    Graph.importJson(data);
                } catch (err) {
                    this.setStatus('JSON inválido: ' + err.message, 'error');
                }
            };
            reader.readAsText(file);
        };
    },

    bindTopbar() {
        document.getElementById('btn-fit').addEventListener('click', () => Graph.fit());
        document.getElementById('btn-clear').addEventListener('click', () => Graph.clear());
        document.getElementById('btn-undo').addEventListener('click', () => Graph.undo());
        document.getElementById('btn-redo').addEventListener('click', () => Graph.redo());
        document.getElementById('btn-save').addEventListener('click', () => this.saveInvestigation());
        document.getElementById('btn-export').addEventListener('click', () => this.exportGraph());
        document.getElementById('btn-import').addEventListener('click', () => this.importGraph());

        // Sidebar tabs (issue #130)
        document.querySelectorAll('.sidebar-tab').forEach((tab) => {
            tab.addEventListener('click', () => {
                this.setActiveSidebarTab(tab.dataset.tab);
            });
        });

        document.getElementById('btn-theme').addEventListener('click', () => this.toggleTheme());

        document.getElementById('ov-fit').addEventListener('click', () => Graph.fit());
        document.getElementById('ov-relayout').addEventListener('click', () => Graph.relayout());
        document.getElementById('ov-zoom-in').addEventListener('click', () => {
            cy.zoom({ level: cy.zoom() * 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
        });
        document.getElementById('ov-zoom-out').addEventListener('click', () => {
            cy.zoom({ level: cy.zoom() * 0.8, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
        });

        // Sidebar
        document.getElementById('btn-create-inv').addEventListener('click', () => this.createInvestigation());
        document.getElementById('btn-save-key').addEventListener('click', () => this.saveKey());

        // Filtros de investigations (issue #27)
        // Search com debounce de 300ms pra não spammar a API enquanto digita
        const invSearch = document.getElementById('inv-search');
        if (invSearch) {
            let invSearchTimer = null;
            invSearch.addEventListener('input', () => {
                clearTimeout(invSearchTimer);
                invSearchTimer = setTimeout(() => this.loadInvestigations(), 300);
            });
        }
        document.getElementById('inv-status-filter')?.addEventListener('change', () => this.loadInvestigations());
        document.getElementById('inv-sort')?.addEventListener('change', () => this.loadInvestigations());

        // ────────────────────────────────────────────────────────────────
        // Responsive drawers (issue #132 — Lane 3 / JS)
        // Conecta botões hamburger/inspector, overlays e tap no canvas
        // aos métodos toggleSidebar/toggleInspector. Em desktop (>1024px)
        // os botões `.mobile-only` estão hidden via CSS, mas o listener
        // é inofensivo (chama toggleSidebar que detecta viewport).
        // ────────────────────────────────────────────────────────────────

        // Botão hamburger (esquerda)
        const btnHamburger = document.getElementById('btn-hamburger');
        if (btnHamburger) {
            btnHamburger.addEventListener('click', () => this.toggleSidebar());
        }

        // Botão toggle inspector (direita) — topbar mobile
        const btnToggleInspector = document.getElementById('btn-toggle-inspector');
        if (btnToggleInspector) {
            btnToggleInspector.addEventListener('click', () => this.toggleInspector());
        }

        // Overlays (backdrop dos drawers) — clique fecha
        const sidebarOverlay = document.getElementById('sidebar-overlay');
        const inspectorOverlay = document.getElementById('inspector-overlay');
        if (sidebarOverlay) {
            sidebarOverlay.addEventListener('click', () => this.closeAllDrawers());
        }
        if (inspectorOverlay) {
            inspectorOverlay.addEventListener('click', () => this.closeAllDrawers());
        }

        // Tap no canvas Cytoscape fecha drawers em tablet/mobile.
        // Só em <=1024px: em desktop o canvas é a área principal e fechar
        // drawers ao clicar seria incorreto (eles já estão no grid).
        // Guard para cy não estar inicializado (ordem de scripts defensiva).
        if (typeof cy !== 'undefined' && cy && typeof cy.on === 'function') {
            cy.on('tap', () => {
                if (this._isTablet()) this.closeAllDrawers();
            });
        }

        // ESC fecha drawers (separado do listener de atalhos para garantir
        // que sempre funcione, mesmo se o foco estiver em input/textarea).
        // Issue #128: graph.js já trata ESC para limpar seleção — aqui
        // verificamos primeiro se há drawer aberto antes de devolver
        // controle pro listener de graph.js.
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const sidebarOpen = document.getElementById('palette')?.classList.contains('open');
                const inspectorOpen = document.getElementById('inspector')?.classList.contains('open');
                if (sidebarOpen || inspectorOpen) {
                    e.preventDefault();
                    e.stopPropagation();
                    this.closeAllDrawers();
                }
            }
        });

        // ────────────────────────────────────────────────────────────────
        // Shortcuts overlay (issue #133)
        // Fechamento via botão X (#so-close) ou clique no backdrop
        // (o <dialog> em si, fora do .so-form). Esc já é tratado nativamente
        // pelo <form method="dialog"> + <dialog>.showModal().
        // ────────────────────────────────────────────────────────────────
        const soClose = document.getElementById('so-close');
        if (soClose) {
            soClose.addEventListener('click', () => {
                const overlay = document.getElementById('shortcuts-overlay');
                if (overlay && overlay.open) overlay.close();
            });
        }
        const shortcutsOverlay = document.getElementById('shortcuts-overlay');
        if (shortcutsOverlay) {
            shortcutsOverlay.addEventListener('click', (e) => {
                if (e.target === shortcutsOverlay) {
                    shortcutsOverlay.close();
                }
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                if (e.shiftKey) {
                    if (e.key === 'T' || e.key === 't') {
                        // Theme toggle (issue #126)
                        e.preventDefault();
                        this.toggleTheme();
                        return;
                    }
                    if (e.key === 'Z' || e.key === 'z') {
                        e.preventDefault();
                        Graph.redo();
                        return;
                    }
                    // Issue #130: atalho Cmd/Ctrl+Shift+R — re-run last transform
                    if (e.key === 'R' || e.key === 'r') {
                        e.preventDefault();
                        if (window.TransformHub && typeof window.TransformHub.runLastTransform === 'function') {
                            window.TransformHub.runLastTransform();
                        }
                        return;
                    }
                } else {
                    if (e.key === 'z' || e.key === 'Z') {
                        e.preventDefault();
                        Graph.undo();
                        return;
                    }
                    if (e.key === 'y' || e.key === 'Y') {
                        e.preventDefault();
                        Graph.redo();
                        return;
                    }
                    // Issue #128: atalhos de sidebar tabs
                    if (e.key === '1' || e.key === '2' || e.key === '3' || e.key === '4') {
                        e.preventDefault();
                        this.switchSidebarTab(parseInt(e.key, 10));
                        return;
                    }
                    // Issue #128: atalho Save (Ctrl/Cmd+S)
                    if (e.key === 's' || e.key === 'S') {
                        e.preventDefault();
                        const btn = document.getElementById('btn-save');
                        if (btn) btn.click();
                        return;
                    }
                    // Issue #130: atalho Cmd/Ctrl+R — switch para tab transforms + run last selected
                    if (e.key === 'r' || e.key === 'R') {
                        e.preventDefault();
                        this.setActiveSidebarTab('transforms');
                        if (window.TransformHub && typeof window.TransformHub.runLastTransform === 'function') {
                            setTimeout(() => window.TransformHub.runLastTransform(), 100);
                        }
                        return;
                    }
                    // Issue #132: atalho Cmd/Ctrl+B — toggle sidebar (esquerda).
                    // Conflita com bookmark do Chrome (Cmd+B) — aceitamos o trade-off
                    // porque em contexto da app o usuário raramente quer bookmarks.
                    if (e.key === 'b' || e.key === 'B') {
                        e.preventDefault();
                        this.toggleSidebar();
                        return;
                    }
                    // Issue #132: atalho Cmd/Ctrl+I — toggle inspector (direita).
                    if (e.key === 'i' || e.key === 'I') {
                        e.preventDefault();
                        this.toggleInspector();
                        return;
                    }
                    // Issue #133: command palette toggle (Cmd/Ctrl+K)
                    if (e.key === 'k' || e.key === 'K') {
                        e.preventDefault();
                        if (window.CommandPaletteUI) {
                            window.CommandPaletteUI.toggle();
                        }
                        return;
                    }
                }
            } else if (e.key === 'f' || e.key === 'F') {
                if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
                e.preventDefault();
                Graph.fit();
                return;
            } else if ((e.key === 'Delete' || e.key === 'Backspace') && Graph.selected) {
                e.preventDefault();
                if (Graph.selected.isNode()) {
                    Modal.confirm({
                        title: 'Remover entidade?',
                        message: 'Esta ação removerá a entidade e seus vínculos.',
                        danger: true,
                        onConfirm: () => this.deleteNode(Graph.selected.id()),
                    });
                } else if (Graph.selected.isEdge()) {
                    this.deleteEdge(Graph.selected.id());
                }
            } else if (e.key === '?' && !this._isEditable(e.target)) {
                // Issue #133: shortcuts overlay (?) — gate por isEditable
                // para não disparar enquanto o usuário digita em um campo.
                e.preventDefault();
                const overlay = document.getElementById('shortcuts-overlay');
                if (overlay && !overlay.open) {
                    overlay.showModal();
                    if (window.App && typeof window.App.announce === 'function') {
                        window.App.announce('Atalhos de teclado abertos', 'polite');
                    }
                    setTimeout(() => document.getElementById('so-close')?.focus(), 0);
                }
            }
        });

        // Health check periódico
        this.checkConnections();
        setInterval(() => this.checkConnections(), 15000);
    },

    async checkConnections() {
        try {
            const r = await fetch('/health');
            if (r.ok) {
                document.getElementById('dot-neo4j').classList.remove('off');
                document.getElementById('dot-pg').classList.remove('off');
            } else {
                throw new Error('not ok');
            }
        } catch {
            document.getElementById('dot-neo4j').classList.add('off');
            document.getElementById('dot-pg').classList.add('off');
        }
    },

    init() {
        // Apply theme before rendering (prevents flash of wrong theme)
        this.applyStoredTheme();
        this.watchSystemTheme();
        Inspector.init();
        // Issue #133: command palette init — registra listeners do <dialog>
        // e dos atalhos. Deve rodar antes de bindTopbar() para que o botão
        // de fechar (#so-close) já esteja disponível.
        if (window.CommandPaletteUI && typeof window.CommandPaletteUI.init === 'function') {
            window.CommandPaletteUI.init();
        }
        Palette.init();
        Graph.init('cy');
        // Issue #131: inicializa o painel de busca/filtro depois do Graph
        // (precisa de window.cy para bind dos listeners de add/remove).
        if (window.SearchPanel && typeof window.SearchPanel.init === 'function') {
            window.SearchPanel.init();
        }
        // Issue #130: Transform Hub — popula a árvore de transforms
        if (window.TransformHub && typeof window.TransformHub.init === 'function') {
            window.TransformHub.init();
        }
        this.bindTopbar();

        // ────────────────────────────────────────────────────────────────
        // Responsive resize listener (issue #132 — Lane 3 / JS)
        // Debounce de 200ms para evitar storms de cy.resize() enquanto
        // o usuário arrasta a janela. Após o debounce:
        //   1. cy.resize() — Cytoscape recalcula viewport/dimensions
        //   2. Graph.fit() — se houver nodes, recentraliza o grafo
        //   3. closeAllDrawers() em desktop — evita drawer "preso" aberto
        //      após rotação de tablet (viewport cruzou o breakpoint).
        // Guard `typeof cy !== 'undefined'` cobre ordem defensiva de scripts.
        // ────────────────────────────────────────────────────────────────
        let resizeTimer = null;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                if (typeof cy !== 'undefined' && cy) {
                    try {
                        cy.resize();
                        if (cy.elements().length > 0) {
                            Graph.fit();
                        }
                    } catch (e) {
                        // cy disposed ou DOM em estado inválido — silencioso
                    }
                }
                // Em desktop, force fechar drawers mobile.
                if (!this._isTablet()) {
                    this.closeAllDrawers();
                }
            }, 200);
        });

        this.loadInvestigations();
        this.loadKeyServices();
        this.loadKeys();
        this.setStatus('Pronto. Arraste entidades da paleta para o canvas.');
        this.loadUser();
    },

    async loadUser() {
        const user = await OpenMAuth.bootstrap();
        if (user) {
            // Issue #130: armazena o currentUser no App para uso por setActiveSidebarTab
            // (que precisa aplicar RBAC gates via OpenMPermissions).
            this.currentUser = user;

            const el = document.getElementById('user-email');
            if (el) el.textContent = user.email;

            // Exibe o role como badge ao lado do email (issue #3).
            const roleEl = document.getElementById('user-role');
            if (roleEl) {
                roleEl.textContent = user.role;
                roleEl.dataset.role = user.role;
            }

            // Esconde elementos cujo data-roles não inclui o role do user.
            if (window.OpenMPermissions) {
                window.OpenMPermissions.applyRoleGates(user);
            }
        }
        // Se bootstrap falhou, já redirecionou pra /login.
    },
};

window.App = App;

function bootApp() {
    if (window.App && window.App.init) {
        window.App.init();
    } else {
        document.addEventListener('app-ready', () => window.App.init(), { once: true });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootApp);
} else {
    bootApp();
}
