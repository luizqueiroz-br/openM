/**
 * Inspector (issue #129 — 3 tabs Maltego-style: Overview / Properties / Sightings).
 * Usa <wa-tab-group> (Issue #127) com fallback HTML+CSS.
 * Reaproveita OpenMAPI.listSightings (Issue #129 backend) para a timeline.
 */
(function () {
    'use strict';

    const Inspector = {
        el: null,
        currentSelection: null,
        currentType: null, // 'node' | 'edge' | null
        sightingsAbort: null,        // AbortController em curso
        sightingsCache: new Map(),   // key: `${entityId}|${category}` → array
        _sightingsCategory: 'all',
        _currentNodeId: null,        // ref para o node atual (capturado no showNode)
    };

    function escapeHtml(s) {
        if (s == null) return '';
        return String(s).replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }

    function getEntityMeta(type) {
        // ENTITY_ICONS é global (icons.js). Fallback para um dict inline.
        if (typeof ENTITY_ICONS !== 'undefined' && ENTITY_ICONS) {
            return ENTITY_ICONS[type] || ENTITY_ICONS.Generic
                || { icon: 'fa-circle', lucide: 'circle', color: '#64748b', label: type };
        }
        return { icon: 'fa-circle', lucide: 'circle', color: '#64748b', label: type };
    }

    function waReady() {
        return typeof window !== 'undefined'
            && !!window.customElements
            && !!customElements.get('wa-tab-group')
            && !!customElements.get('wa-tab')
            && !!customElements.get('wa-tab-panel');
    }

    function tabsMarkup(wa) {
        if (wa) {
            return `<wa-tab-group id="inspector-tab-group">
                <wa-tab slot="nav" panel="overview" active>Visão geral</wa-tab>
                <wa-tab slot="nav" panel="properties">Propriedades</wa-tab>
                <wa-tab slot="nav" panel="sightings">Sightings</wa-tab>
            </wa-tab-group>`;
        }
        return `<div class="inspector-tabs">
            <button class="inspector-tab active" data-tab="overview" type="button">Visão geral</button>
            <button class="inspector-tab" data-tab="properties" type="button">Propriedades</button>
            <button class="inspector-tab" data-tab="sightings" type="button">Sightings</button>
        </div>`;
    }

    function renderOverview(node) {
        const meta = getEntityMeta(node.type);
        const source = node._source || 'manual';
        const sourceBadge = source === 'transform'
            ? '<span class="inspector-badge inspector-badge-transform">transform</span>'
            : '<span class="inspector-badge inspector-badge-manual">manual</span>';
        const id = node.id || '';
        const idShort = id.length > 12 ? id.substring(0, 12) + '…' : id;
        const value = node.label || node.value || '';
        const created = node.created_at || node._created_at || '';
        const flagged = node.virustotal_flagged
            ? '<span class="inspector-badge inspector-badge-flagged">flagged</span>'
            : '';
        const summarySuffix = source === 'transform' ? ' via transform' : ' manualmente';

        return `
            <div class="inspector-overview">
                <div class="inspector-overview-header">
                    <div class="inspector-overview-icon" style="background:${meta.color}">
                        <i data-lucide="${meta.lucide || 'circle'}"></i>
                    </div>
                    <div class="inspector-overview-meta">
                        <div class="inspector-overview-type">${escapeHtml(node.type || '')}</div>
                        <div class="inspector-overview-value">${escapeHtml(value)}</div>
                        <div class="inspector-overview-id">${escapeHtml(idShort)}</div>
                    </div>
                </div>
                <div class="inspector-overview-badges">
                    ${sourceBadge}${flagged}
                </div>
                <p class="inspector-overview-summary">
                    ${escapeHtml(node.type || 'Entidade')} criado${created ? ' em ' + new Date(created).toLocaleDateString('pt-BR') : ''}${summarySuffix}.
                </p>
                <div class="inspector-overview-actions">
                    <button class="btn sm" id="ins-action-run" type="button">
                        <i data-lucide="zap"></i> Rodar transform
                    </button>
                    <button class="btn sm" id="ins-action-edit" type="button">
                        <i data-lucide="pen"></i> Editar propriedades
                    </button>
                    <button class="btn sm" id="ins-action-copy" type="button" title="Copiar ID">
                        <i data-lucide="copy"></i> Copiar ID
                    </button>
                    <button class="btn sm" id="ins-action-root" type="button">
                        <i data-lucide="anchor"></i> Definir como raiz
                    </button>
                </div>
            </div>
        `;
    }

    function renderProperties(node) {
        const props = Object.entries(node).filter(([k]) =>
            !['id', 'label', 'type'].includes(k) && !k.startsWith('_')
        );

        const propsHtml = props.length === 0
            ? '<div class="empty">Sem propriedades extras</div>'
            : props.map(([k, v]) => {
                const raw = typeof v === 'object' ? JSON.stringify(v) : String(v);
                return `
                <div class="prop-row" data-key="${escapeHtml(k)}">
                    <span class="k">${escapeHtml(k)}</span>
                    <span class="v" title="${escapeHtml(raw)}">${escapeHtml(raw)}</span>
                </div>
            `;
            }).join('');

        return `
            <div class="inspector-properties">
                <div class="inspector-search-bar">
                    <i data-lucide="search"></i>
                    <input type="text" id="ins-props-search" placeholder="Filtrar propriedades..." aria-label="Filtrar propriedades" />
                </div>
                <div class="inspector-props-list" id="ins-props-list">
                    ${propsHtml}
                </div>
                <button class="btn sm" id="ins-action-add-prop" type="button" style="width:100%; margin-top:0.5rem">
                    <i data-lucide="plus"></i> Adicionar propriedade
                </button>
            </div>
        `;
    }

    function renderSightingsFiltersHTML() {
        const cur = Inspector._sightingsCategory || 'all';
        const cats = [
            { id: 'all', label: 'Todos' },
            { id: 'transforms', label: 'Transforms' },
            { id: 'edits', label: 'Edições' },
            { id: 'manual', label: 'Manual' },
        ];
        return cats.map((c) => `
            <button class="sighting-filter ${c.id === cur ? 'active' : ''}" data-category="${c.id}" type="button" role="tab" aria-selected="${c.id === cur}">${c.label}</button>
        `).join('');
    }

    function renderSightingsSkeleton() {
        return `
            <div class="sightings-filters" role="tablist" aria-label="Filtro de sightings">
                ${renderSightingsFiltersHTML()}
            </div>
            <div class="sightings-list" id="ins-sightings-list" aria-live="polite" aria-busy="true">
                <div class="sighting sighting-skeleton">Carregando timeline…</div>
            </div>
        `;
    }

    function renderSightingsList(sightings) {
        if (!sightings || sightings.length === 0) {
            return `
                <div class="sightings-filters" role="tablist" aria-label="Filtro de sightings">
                    ${renderSightingsFiltersHTML()}
                </div>
                <div class="sightings-list" id="ins-sightings-list" aria-live="polite">
                    <div class="sighting sighting-empty">Nenhum evento registrado para esta entidade.</div>
                </div>
            `;
        }
        return `
            <div class="sightings-filters" role="tablist" aria-label="Filtro de sightings">
                ${renderSightingsFiltersHTML()}
            </div>
            <div class="sightings-list" id="ins-sightings-list" aria-live="polite">
                ${sightings.map(renderSightingItem).join('')}
            </div>
        `;
    }

    function renderSightingItem(s) {
        const icon = s.type === 'transform' ? 'zap'
            : s.type === 'create' ? 'plus-circle'
            : s.type === 'update' ? 'edit'
            : s.type === 'delete' ? 'trash-2'
            : 'activity';
        const actor = s.actor ? (s.actor.email || `user#${s.actor.id}`) : 'sistema';
        const when = s.created_at ? formatRelative(s.created_at) : '';
        const dur = s.metadata && s.metadata.duration_ms != null
            ? ` <span class="sighting-duration">(${s.metadata.duration_ms}ms)</span>` : '';
        const newCounts = (s.metadata && (s.metadata.new_entities_count || s.metadata.new_relationships_count))
            ? ` <span class="sighting-counts">+${s.metadata.new_entities_count || 0} nós, +${s.metadata.new_relationships_count || 0} arestas</span>`
            : '';

        return `
            <div class="sighting" data-id="${s.id}">
                <div class="sighting-icon sighting-type-${s.type}">
                    <i data-lucide="${icon}"></i>
                </div>
                <div class="sighting-body">
                    <div class="sighting-title">${escapeHtml(s.title || s.action)}</div>
                    <div class="sighting-subtitle">${escapeHtml(s.subtitle || '')}${dur}${newCounts}</div>
                    <div class="sighting-meta">
                        <span class="sighting-actor">${escapeHtml(actor)}</span>
                        <span class="sighting-when">${escapeHtml(when)}</span>
                    </div>
                </div>
            </div>
        `;
    }

    function formatRelative(iso) {
        try {
            const t = new Date(iso).getTime();
            if (isNaN(t)) return '';
            const diff = Date.now() - t;
            const min = 60_000, hour = 60 * min, day = 24 * hour;
            if (diff < 0) return new Date(iso).toLocaleDateString('pt-BR');
            if (diff < min) return 'agora';
            if (diff < hour) return `${Math.floor(diff / min)}min atrás`;
            if (diff < day) return `${Math.floor(diff / hour)}h atrás`;
            const d = Math.floor(diff / day);
            if (d < 7) return `${d}d atrás`;
            return new Date(iso).toLocaleDateString('pt-BR');
        } catch (e) {
            return '';
        }
    }

    function bindSightingsFilterClicks(nodeId) {
        const buttons = document.querySelectorAll('.sighting-filter');
        buttons.forEach((btn) => {
            // Clonar para remover listeners anteriores.
            const newBtn = btn.cloneNode(true);
            btn.parentNode.replaceChild(newBtn, btn);
            newBtn.addEventListener('click', () => {
                const cat = newBtn.getAttribute('data-category');
                loadSightings(nodeId, cat);
            });
        });
    }

    async function loadSightings(nodeId, category) {
        category = category || 'all';
        Inspector._sightingsCategory = category;

        if (!nodeId) return;

        // Abort fetch anterior
        if (Inspector.sightingsAbort) {
            try { Inspector.sightingsAbort.abort(); } catch (e) { /* ignore */ }
        }
        const ac = new AbortController();
        Inspector.sightingsAbort = ac;

        // Cache
        const cacheKey = `${nodeId}|${category}`;
        if (Inspector.sightingsCache.has(cacheKey)) {
            renderSightingsIntoDOM(Inspector.sightingsCache.get(cacheKey), nodeId);
            return;
        }

        // Skeleton no DOM
        const listEl = document.getElementById('ins-sightings-list');
        if (listEl) {
            listEl.setAttribute('aria-busy', 'true');
            listEl.innerHTML = '<div class="sighting sighting-skeleton">Carregando timeline…</div>';
        }

        // Atualiza o estado visual dos botões de filtro
        document.querySelectorAll('.sighting-filter').forEach((b) => {
            const isActive = b.getAttribute('data-category') === category;
            b.classList.toggle('active', isActive);
            b.setAttribute('aria-selected', isActive ? 'true' : 'false');
        });

        try {
            const data = await window.OpenMAPI.listSightings(nodeId, { category, limit: 50 });
            if (ac.signal.aborted) return;
            const arr = (data && data.sightings) || [];
            Inspector.sightingsCache.set(cacheKey, arr);
            if (ac.signal.aborted) return;
            renderSightingsIntoDOM(arr, nodeId);
        } catch (e) {
            if (ac.signal.aborted) return;
            console.error('Inspector.loadSightings failed', e);
            const list = document.getElementById('ins-sightings-list');
            if (list) {
                list.removeAttribute('aria-busy');
                list.innerHTML = '<div class="sighting sighting-empty">Erro ao carregar timeline.</div>';
            }
            if (window.App && typeof window.App.announce === 'function') {
                window.App.announce('Erro ao carregar timeline', 'assertive');
            }
        }
    }

    function renderSightingsIntoDOM(arr, nodeId) {
        const container = document.querySelector('.inspector-sightings-container');
        if (!container) return;
        container.innerHTML = renderSightingsList(arr);
        // Re-render Lucide icons
        if (window.lucide && window.lucide.createIcons) {
            window.lucide.createIcons();
        }
        // Re-bind filter clicks
        bindSightingsFilterClicks(nodeId);
    }

    // ─────────────────────────────────────────────────────────────────────
    // showNode — 3 tabs Maltego-style
    // ─────────────────────────────────────────────────────────────────────
    Inspector.showNode = function (node) {
        this.currentSelection = node;
        this.currentType = 'node';
        this._currentNodeId = node.id;

        // Limpar sightings cache + abort
        if (this.sightingsAbort) {
            try { this.sightingsAbort.abort(); } catch (e) { /* ignore */ }
            this.sightingsAbort = null;
        }
        this.sightingsCache.clear();
        this._sightingsCategory = 'all';

        const wa = waReady();

        const overviewHTML = renderOverview(node);
        const propsHTML = renderProperties(node);

        const tabsHTML = tabsMarkup(wa);
        const panesHTML = wa
            ? `<wa-tab-panel name="overview">${overviewHTML}</wa-tab-panel>
               <wa-tab-panel name="properties">${propsHTML}</wa-tab-panel>
               <wa-tab-panel name="sightings"><div class="inspector-sightings-container">${renderSightingsSkeleton()}</div></wa-tab-panel>`
            : `<div class="tab-pane" data-pane="overview">${overviewHTML}</div>
               <div class="tab-pane" data-pane="properties" style="display:none">${propsHTML}</div>
               <div class="tab-pane" data-pane="sightings" style="display:none"><div class="inspector-sightings-container">${renderSightingsSkeleton()}</div></div>`;

        this.el.innerHTML = `
            <div class="inspector-header">
                <div class="icon" style="background:${getEntityMeta(node.type).color}">
                    <i data-lucide="${getEntityMeta(node.type).lucide || 'circle'}"></i>
                </div>
                <div class="meta">
                    <div class="type">${escapeHtml(node.type || 'Nó')}</div>
                    <div class="value">${escapeHtml((node.label || node.value || node.id || '').substring(0, 32))}</div>
                </div>
            </div>
            ${tabsHTML}
            <div class="inspector-body">
                ${wa ? panesHTML.replace(/^/, '') : panesHTML}
            </div>
        `;

        // Se WA, os wa-tab-panel ficam dentro do wa-tab-group, fora do .inspector-body.
        if (wa) {
            // Reorganiza: mover os wa-tab-panels para dentro do wa-tab-group
            const tabGroup = this.el.querySelector('#inspector-tab-group');
            const body = this.el.querySelector('.inspector-body');
            if (tabGroup && body) {
                const panels = body.querySelectorAll('wa-tab-panel');
                panels.forEach((p) => tabGroup.appendChild(p));
                // Remove o .inspector-body vazio (a própria wa-tab-group cuida do layout)
                body.remove();
            }
        }

        // Re-render Lucide
        if (window.lucide && window.lucide.createIcons) {
            window.lucide.createIcons();
        }

        // Bind WA ou fallback
        if (wa) {
            const tabGroup = this.el.querySelector('#inspector-tab-group');
            if (tabGroup) {
                tabGroup.addEventListener('tab-show', (e) => {
                    const name = e.detail && e.detail.name;
                    if (name === 'sightings') {
                        loadSightings(node.id, Inspector._sightingsCategory);
                    }
                });
            }
        } else {
            // Fallback tabs (button + .tab-pane display)
            this.el.querySelectorAll('.inspector-tab').forEach((tab) => {
                tab.addEventListener('click', () => {
                    const name = tab.getAttribute('data-tab');
                    this.el.querySelectorAll('.inspector-tab').forEach((t) => t.classList.remove('active'));
                    this.el.querySelectorAll('.tab-pane').forEach((p) => p.style.display = 'none');
                    tab.classList.add('active');
                    const pane = this.el.querySelector(`.tab-pane[data-pane="${name}"]`);
                    if (pane) pane.style.display = 'block';
                    if (name === 'sightings') {
                        loadSightings(node.id, Inspector._sightingsCategory);
                    }
                });
            });
        }

        // Bind overview actions
        const runBtn = this.el.querySelector('#ins-action-run');
        if (runBtn) {
            runBtn.addEventListener('click', () => {
                if (window.App && typeof window.App.runTransform === 'function') {
                    // null = run all (assinatura App.runTransform(node, transformName))
                    window.App.runTransform(node, null);
                }
            });
        }
        const editBtn = this.el.querySelector('#ins-action-edit');
        if (editBtn) {
            editBtn.addEventListener('click', () => {
                if (window.Modal && typeof window.Modal.editProperties === 'function') {
                    window.Modal.editProperties({
                        node,
                        onSave: (newProps) => window.App && window.App.updateNodeProperties
                            && window.App.updateNodeProperties(node.id, newProps),
                    });
                }
            });
        }
        const copyBtn = this.el.querySelector('#ins-action-copy');
        if (copyBtn) {
            copyBtn.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(node.id || '');
                    if (window.App && typeof window.App.announce === 'function') {
                        window.App.announce('ID copiado para área de transferência', 'polite');
                    }
                } catch (e) { /* ignore */ }
            });
        }
        const rootBtn = this.el.querySelector('#ins-action-root');
        if (rootBtn) {
            rootBtn.addEventListener('click', () => {
                if (window.Graph && typeof window.Graph.setRoot === 'function') {
                    // Graph.setRoot espera id (string)
                    window.Graph.setRoot(node.id);
                }
            });
        }

        // Bind properties search
        const propsSearch = this.el.querySelector('#ins-props-search');
        const propsList = this.el.querySelector('#ins-props-list');
        if (propsSearch && propsList) {
            propsSearch.addEventListener('input', () => {
                const q = (propsSearch.value || '').toLowerCase();
                propsList.querySelectorAll('.prop-row').forEach((row) => {
                    const k = (row.getAttribute('data-key') || '').toLowerCase();
                    row.style.display = k.includes(q) ? '' : 'none';
                });
            });
        }

        const addPropBtn = this.el.querySelector('#ins-action-add-prop');
        if (addPropBtn) {
            addPropBtn.addEventListener('click', () => {
                if (window.Modal && typeof window.Modal.editProperties === 'function') {
                    window.Modal.editProperties({
                        node,
                        onSave: (newProps) => window.App && window.App.updateNodeProperties
                            && window.App.updateNodeProperties(node.id, newProps),
                    });
                }
            });
        }

        // Bind sightings filter (eager: já que o skeleton está renderizado)
        bindSightingsFilterClicks(node.id);

        // Dispatch event
        window.dispatchEvent(new CustomEvent('selection-changed', { detail: { node } }));
    };

    Inspector.showEdge = function (edge) {
        this.currentSelection = edge;
        this.currentType = 'edge';
        // Show edge (sem tabs, monolítico como antes)
        this.el.innerHTML = `
            <div class="inspector-header">
                <div class="icon" style="background:var(--text-faint)">
                    <i data-lucide="link"></i>
                </div>
                <div class="meta">
                    <div class="type">Vínculo</div>
                    <div class="value">${escapeHtml(edge.label || 'REL')}</div>
                </div>
            </div>
            <div class="inspector-body">
                <div class="prop-row">
                    <span class="k">ID</span>
                    <span class="v mono">${escapeHtml((edge.id || '').substring(0, 12))}…</span>
                </div>
                <div class="prop-row">
                    <span class="k">De</span>
                    <span class="v mono">${escapeHtml((edge.source || '').substring(0, 8))}…</span>
                </div>
                <div class="prop-row">
                    <span class="k">Para</span>
                    <span class="v mono">${escapeHtml((edge.target || '').substring(0, 8))}…</span>
                </div>
                ${Object.entries(edge).filter(([k]) => !['id','label','source','target'].includes(k))
                    .map(([k, v]) => {
                        const raw = typeof v === 'object' ? JSON.stringify(v) : String(v);
                        return `
                        <div class="prop-row">
                            <span class="k">${escapeHtml(k)}</span>
                            <span class="v">${escapeHtml(raw)}</span>
                        </div>
                    `;
                    }).join('')}
                <button class="btn danger" id="delete-edge" style="width:100%; margin-top:1rem" type="button">
                    <i data-lucide="trash-2"></i>Remover vínculo
                </button>
            </div>
        `;
        if (window.lucide && window.lucide.createIcons) window.lucide.createIcons();
        const delBtn = this.el.querySelector('#delete-edge');
        if (delBtn) {
            delBtn.addEventListener('click', () => {
                if (window.Modal && typeof window.Modal.confirm === 'function') {
                    window.Modal.confirm({
                        title: 'Remover vínculo?',
                        message: 'Esta ação removerá o vínculo entre as entidades.',
                        danger: true,
                        onConfirm: () => window.App && window.App.deleteEdge && window.App.deleteEdge(edge.id),
                    });
                }
            });
        }
    };

    Inspector.showEmpty = function () {
        this.currentSelection = null;
        this.currentType = null;
        this._currentNodeId = null;
        if (this.sightingsAbort) {
            try { this.sightingsAbort.abort(); } catch (e) { /* ignore */ }
            this.sightingsAbort = null;
        }
        this.sightingsCache.clear();
        this.el.innerHTML = `
            <div class="inspector-empty">
                <i data-lucide="info" style="font-size:2rem; margin-bottom:0.5rem; display:block"></i>
                Selecione um nó ou aresta para ver detalhes
            </div>
        `;
        if (window.lucide && window.lucide.createIcons) window.lucide.createIcons();
        window.dispatchEvent(new CustomEvent('selection-cleared'));
    };

    Inspector.init = function () {
        this.el = document.getElementById('inspector-content');
    };

    // Bind to window
    window.Inspector = Inspector;
})();
