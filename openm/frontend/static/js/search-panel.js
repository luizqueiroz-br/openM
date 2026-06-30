/**
 * Graph Search & Filter Panel (issue #131).
 * Dependências: Fuse.js (window.Fuse), Cytoscape (window.cy), Graph (window.Graph).
 * Namespace exportado: window.SearchPanel.
 */
(function () {
    'use strict';

    const ENTITY_TYPES = [
        'Domain', 'IPAddress', 'URL', 'DNS',
        'Email', 'Phone',
        'Person', 'PessoaFisica', 'PessoaJuridica',
        'Empresa', 'Estabelecimento', 'CNPJ', 'CompanhiaAberta', 'Acao', 'Ticker',
        'ProcessoJudicial', 'Sancao', 'OrgaoSancionador',
        'Endereco', 'Municipio',
        'BankAccount', 'Device', 'FileHash',
    ];

    // Mapeia EntityType -> kebab-case para lookup de tokens CSS
    const TYPE_KEBAB = {
        Domain: 'domain', IPAddress: 'ip', URL: 'url', DNS: 'dns',
        Email: 'email', Phone: 'phone',
        Person: 'person', PessoaFisica: 'pessoa-fisica', PessoaJuridica: 'pessoa-juridica',
        Empresa: 'empresa', Estabelecimento: 'estabelecimento', CNPJ: 'cnpj',
        CompanhiaAberta: 'companhia-aberta', Acao: 'acao', Ticker: 'ticker',
        ProcessoJudicial: 'processo', Sancao: 'sancao', OrgaoSancionador: 'orgao',
        Endereco: 'endereco', Municipio: 'municipio',
        BankAccount: 'bank', Device: 'device', FileHash: 'file-hash',
    };

    function kebab(type) {
        return TYPE_KEBAB[type] || type.toLowerCase();
    }

    function getEntityColor(type) {
        const root = document.documentElement;
        const v = getComputedStyle(root).getPropertyValue(`--c-${kebab(type)}`).trim();
        return v || '#64748b';
    }

    // ─────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────

    const state = {
        open: false,
        searchQuery: '',
        hiddenTypes: new Set(),   // types the user unchecked
        neighborhood: {
            enabled: false,
            depth: 1,
            rootId: null,
        },
    };

    let fuse = null;            // Fuse instance (lazy)
    let fuseIndex = [];         // [{ id, label, type, ...data }]
    let fuseIndexNeedsRefresh = true;
    let debounceTimer = null;
    let currentInvestigationId = null;

    // ─────────────────────────────────────────────────────────────────────
    // Persistence (localStorage keyed by investigation)
    // ─────────────────────────────────────────────────────────────────────

    function loadState(invId) {
        if (!invId) return null;
        try {
            const raw = localStorage.getItem(`openm.graph-filter.${invId}`);
            return raw ? JSON.parse(raw) : null;
        } catch (e) { return null; }
    }

    function saveState() {
        if (!currentInvestigationId) return;
        try {
            localStorage.setItem(
                `openm.graph-filter.${currentInvestigationId}`,
                JSON.stringify({
                    searchQuery: state.searchQuery,
                    hiddenTypes: Array.from(state.hiddenTypes),
                    neighborhood: state.neighborhood,
                })
            );
        } catch (e) { /* ignore quota */ }
    }

    function debouncedSave() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(saveState, 500);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Render checkboxes (called once on init)
    // ─────────────────────────────────────────────────────────────────────

    function renderTypeCheckboxes() {
        const container = document.getElementById('graph-search-types');
        if (!container) return;
        container.innerHTML = '';
        ENTITY_TYPES.forEach((type) => {
            const row = document.createElement('label');
            row.className = 'gsp-type-row';
            row.setAttribute('data-type', type);
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'gsp-type-checkbox';
            checkbox.checked = true;
            checkbox.setAttribute('data-type', type);
            checkbox.setAttribute('aria-label', `Mostrar ${type}`);
            const swatch = document.createElement('span');
            swatch.className = 'gsp-type-swatch';
            swatch.style.background = getEntityColor(type);
            const label = document.createElement('span');
            label.className = 'gsp-type-label';
            label.textContent = type;
            const count = document.createElement('span');
            count.className = 'gsp-type-count';
            count.textContent = '0';
            row.appendChild(checkbox);
            row.appendChild(swatch);
            row.appendChild(label);
            row.appendChild(count);
            container.appendChild(row);
            checkbox.addEventListener('change', () => onTypeToggle(type, checkbox.checked));
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Apply (the heart of the filter)
    // ─────────────────────────────────────────────────────────────────────

    function apply() {
        if (!window.cy) return;
        // 1. Re-index Fuse if needed
        if (!fuse || fuseIndexNeedsRefresh) {
            rebuildFuseIndex();
        }
        // 2. Clear previous match/filter classes
        window.cy.nodes().removeClass('cy-node-match cy-node-filtered-out');
        window.cy.edges().removeClass('cy-node-filtered-out');
        // 3. Search matches
        let matchedIds = new Set();
        if (state.searchQuery && fuse) {
            const results = fuse.search(state.searchQuery);
            results.forEach((r) => matchedIds.add(r.item.id));
            window.cy.nodes().forEach((n) => {
                if (matchedIds.has(n.id())) n.addClass('cy-node-match');
            });
        }
        // 4. Type filter
        state.hiddenTypes.forEach((type) => {
            const nodes = window.cy.nodes().filter((n) => n.data('type') === type);
            nodes.addClass('cy-node-filtered-out');
        });
        // 5. Neighborhood
        if (state.neighborhood.enabled && state.neighborhood.rootId) {
            const nbhd = window.Graph.getNeighborhood(state.neighborhood.rootId, state.neighborhood.depth);
            if (nbhd && nbhd.length) {
                window.cy.nodes().difference(nbhd).addClass('cy-node-filtered-out');
            }
        }
        // 6. Cascade edges (if either endpoint is hidden, hide the edge)
        window.cy.edges().forEach((e) => {
            if (
                e.source().hasClass('cy-node-filtered-out') ||
                e.target().hasClass('cy-node-filtered-out')
            ) {
                e.addClass('cy-node-filtered-out');
            }
        });
        // 7. Update UI
        updateCounters();
        // 8. Announce to screen reader
        if (window.App && typeof window.App.announce === 'function') {
            const visible = window.cy.nodes().not('.cy-node-filtered-out').length;
            const total = window.cy.nodes().length;
            window.App.announce(
                `Filtro aplicado. ${visible} de ${total} nodes visíveis.`,
                'polite'
            );
        }
        debouncedSave();
    }

    function rebuildFuseIndex() {
        if (!window.cy) return;
        fuseIndex = window.cy.nodes().map((n) => {
            const d = n.data();
            return {
                id: n.id(),
                label: d.label || d.value || '',
                type: d.type || '',
                // stringified properties for fuzzy search
                properties: JSON.stringify(d || {}),
            };
        });
        if (window.Fuse) {
            fuse = new window.Fuse(fuseIndex, {
                keys: ['label', 'type', 'properties'],
                threshold: 0.4,
                ignoreLocation: true,
                minMatchCharLength: 2,
            });
        }
        fuseIndexNeedsRefresh = false;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Event handlers
    // ─────────────────────────────────────────────────────────────────────

    function onSearchInput(e) {
        state.searchQuery = e.target.value.trim();
        // Debounce 80ms
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(apply, 80);
    }

    function onTypeToggle(type, checked) {
        if (checked) {
            state.hiddenTypes.delete(type);
        } else {
            state.hiddenTypes.add(type);
        }
        apply();
    }

    function onNeighborhoodToggle() {
        const cb = document.getElementById('graph-search-neighborhood-toggle');
        if (!cb) return;
        state.neighborhood.enabled = cb.checked;
        if (state.neighborhood.enabled) {
            // Capture current selection as root
            if (window.Graph && window.Graph.selected) {
                state.neighborhood.rootId = window.Graph.selected.id();
            } else {
                state.neighborhood.rootId = null;
                cb.checked = false;
                state.neighborhood.enabled = false;
                if (window.App && window.App.announce) {
                    window.App.announce('Selecione um nó antes de ativar a vizinhança', 'assertive');
                }
                return;
            }
            // Clear `_highlightNeighborhood` (dimmed) — conflict with filter
            if (typeof window.Graph._clearHighlight === 'function') {
                window.Graph._clearHighlight();
            }
        } else {
            state.neighborhood.rootId = null;
        }
        apply();
    }

    function onNeighborhoodDepthChange() {
        const sel = document.getElementById('graph-search-neighborhood-depth');
        if (!sel) return;
        state.neighborhood.depth = parseInt(sel.value, 10) || 1;
        if (state.neighborhood.enabled) apply();
    }

    function onClear() {
        state.searchQuery = '';
        state.hiddenTypes = new Set();
        state.neighborhood = { enabled: false, depth: 1, rootId: null };
        const input = document.getElementById('graph-search-input');
        if (input) input.value = '';
        const counter = document.getElementById('graph-search-count');
        if (counter) counter.textContent = '0 matches';
        const cb = document.getElementById('graph-search-neighborhood-toggle');
        if (cb) cb.checked = false;
        const sel = document.getElementById('graph-search-neighborhood-depth');
        if (sel) sel.value = '1';
        // Reset all checkboxes
        document.querySelectorAll('.gsp-type-checkbox').forEach((c) => { c.checked = true; });
        // Clear visual
        if (window.cy) {
            window.cy.nodes().removeClass('cy-node-match cy-node-filtered-out');
            window.cy.edges().removeClass('cy-node-filtered-out');
        }
        // Update counters
        updateCounters();
        if (window.App && window.App.announce) {
            window.App.announce('Filtros limpos', 'polite');
        }
        debouncedSave();
    }

    function onPanelToggle() {
        const panel = document.getElementById('graph-search-panel');
        const btn = document.getElementById('btn-search-panel');
        if (!panel || !btn) return;
        const isOpen = !panel.classList.contains('collapsed');
        if (isOpen) {
            panel.classList.add('collapsed');
            btn.setAttribute('aria-pressed', 'false');
            btn.setAttribute('aria-expanded', 'false');
            state.open = false;
        } else {
            panel.classList.remove('collapsed');
            btn.setAttribute('aria-pressed', 'true');
            btn.setAttribute('aria-expanded', 'true');
            state.open = true;
            fuseIndexNeedsRefresh = true;  // rebuild on next apply
            // Focus search input on open
            setTimeout(() => {
                const input = document.getElementById('graph-search-input');
                if (input) input.focus();
            }, 200);
        }
    }

    function onGlobalCmdF(e) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'f' && !e.shiftKey && !e.altKey) {
            e.preventDefault();
            onPanelToggle();
            // If now open, focus the input
            setTimeout(() => {
                const input = document.getElementById('graph-search-input');
                if (input) {
                    input.focus();
                    input.select();
                }
            }, 100);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Counters
    // ─────────────────────────────────────────────────────────────────────

    function updateCounters() {
        if (!window.cy) return;
        // Match counter
        const matchEl = document.getElementById('graph-search-count');
        if (matchEl) {
            const matchCount = window.cy.nodes('.cy-node-match').length;
            matchEl.textContent = `${matchCount} match${matchCount === 1 ? '' : 'es'}`;
        }
        // Per-type counters
        document.querySelectorAll('.gsp-type-checkbox').forEach((cb) => {
            const type = cb.getAttribute('data-type');
            const count = window.cy.nodes().filter((n) => n.data('type') === type).length;
            const row = cb.closest('.gsp-type-row');
            if (row) {
                const countEl = row.querySelector('.gsp-type-count');
                if (countEl) countEl.textContent = String(count);
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Investigation integration
    // ─────────────────────────────────────────────────────────────────────

    function setInvestigationId(id) {
        currentInvestigationId = id;
        if (id) {
            const saved = loadState(id);
            if (saved) {
                // Restore state
                if (typeof saved.searchQuery === 'string') {
                    state.searchQuery = saved.searchQuery;
                    const input = document.getElementById('graph-search-input');
                    if (input) input.value = saved.searchQuery;
                }
                if (Array.isArray(saved.hiddenTypes)) {
                    state.hiddenTypes = new Set(saved.hiddenTypes);
                    document.querySelectorAll('.gsp-type-checkbox').forEach((cb) => {
                        const type = cb.getAttribute('data-type');
                        cb.checked = !state.hiddenTypes.has(type);
                    });
                }
                if (saved.neighborhood && typeof saved.neighborhood === 'object') {
                    state.neighborhood = {
                        enabled: !!saved.neighborhood.enabled,
                        depth: parseInt(saved.neighborhood.depth, 10) || 1,
                        rootId: saved.neighborhood.rootId || null,
                    };
                    const cb = document.getElementById('graph-search-neighborhood-toggle');
                    if (cb) cb.checked = state.neighborhood.enabled;
                    const sel = document.getElementById('graph-search-neighborhood-depth');
                    if (sel) sel.value = String(state.neighborhood.depth);
                }
                apply();
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Graph event listeners (re-index on add/remove)
    // ─────────────────────────────────────────────────────────────────────

    function bindGraphEvents() {
        if (!window.cy) return;
        window.cy.on('add remove data', () => {
            fuseIndexNeedsRefresh = true;
            updateCounters();
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Init
    // ─────────────────────────────────────────────────────────────────────

    function init() {
        renderTypeCheckboxes();
        bindGraphEvents();
        // Bind panel events
        const input = document.getElementById('graph-search-input');
        if (input) input.addEventListener('input', onSearchInput);
        document.querySelectorAll('.gsp-type-checkbox').forEach((cb) => {
            cb.addEventListener('change', () => onTypeToggle(cb.getAttribute('data-type'), cb.checked));
        });
        const nbToggle = document.getElementById('graph-search-neighborhood-toggle');
        if (nbToggle) nbToggle.addEventListener('change', onNeighborhoodToggle);
        const nbDepth = document.getElementById('graph-search-neighborhood-depth');
        if (nbDepth) nbDepth.addEventListener('change', onNeighborhoodDepthChange);
        const clearBtn = document.getElementById('graph-search-clear');
        if (clearBtn) clearBtn.addEventListener('click', onClear);
        const topBtn = document.getElementById('btn-search-panel');
        if (topBtn) topBtn.addEventListener('click', onPanelToggle);
        const closeBtn = document.getElementById('btn-search-panel-close');
        if (closeBtn) closeBtn.addEventListener('click', onPanelToggle);
        // Global Cmd+F
        document.addEventListener('keydown', onGlobalCmdF);
        // Initial counters
        setTimeout(updateCounters, 100);
    }

    // Export
    window.SearchPanel = {
        init,
        apply,
        setInvestigationId,
        open: () => { if (!state.open) onPanelToggle(); },
        close: () => { if (state.open) onPanelToggle(); },
        toggle: onPanelToggle,
        getState: () => state,
    };
})();
