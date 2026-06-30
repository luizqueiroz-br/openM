/**
 * Transform Hub (issue #130).
 * Renderiza árvore de 8 categorias de transforms com busca fuzzy (Fuse.js)
 * e painel de detalhes. Integra com App.runTransform e Graph.selected.
 *
 * Contratos de coordenação (NÃO MUDE):
 *   - Tree:        #th-tree    (role=tree)
 *   - Detail:      #th-detail  (role=region)
 *   - Search:      #th-search  (input.th-search-input)
 *
 * Backend:
 *   - OpenMAPI.listTransforms(entityType) -> GET /api/transforms/<type>
 *   - OpenMAPI.runTransform(...) -> POST /api/run_transform
 *   - App.runTransform(nodeData, name) -> orquestra o run + adiciona nodes/edges
 *   - Graph.selected -> cytoscape node/edge (ou null)
 */
(function () {
    'use strict';

    // 8 categorias canônicas com metadata estática (ícone, transforms esperados)
    const CATEGORIES = [
        {
            id: 'dns',
            label: 'DNS',
            icon: 'network',
            serviceTiers: {
                free: ['resolve_ip', 'reverse_dns', 'dns_records_lookup', 'crtsh_lookup', 'ssl_cert_inspect', 'whois_lookup', 'urlscan_lookup'],
            },
        },
        {
            id: 'cep',
            label: 'CEP / Endereço',
            icon: 'map-pin',
            serviceTiers: { free: ['geoip_lookup'] },
        },
        {
            id: 'identidade',
            label: 'Identidade',
            icon: 'user',
            serviceTiers: {
                free: ['email_to_domain', 'check_fraud_email', 'mac_vendor_lookup'],
                registered: ['hibp_breach_lookup', 'hunter_email_verifier', 'hunter_domain_search', 'person_domain_discovery'],
            },
        },
        {
            id: 'cnpj',
            label: 'CNPJ / Empresas',
            icon: 'building-2',
            placeholder: 'Em breve: cnpj_lookup, cnpj_socios, receita_federal',
        },
        {
            id: 'mercado',
            label: 'Mercado Financeiro',
            icon: 'line-chart',
            serviceTiers: { free: ['iban_swift_validation'] },
        },
        {
            id: 'sancoes',
            label: 'Sanções',
            icon: 'ban',
            serviceTiers: { registered: ['abuseipdb_lookup'], commercial: ['virustotal_lookup'] },
        },
        {
            id: 'judicial',
            label: 'Judicial',
            icon: 'gavel',
            placeholder: 'Em breve: cnj_processos, tjsp_consulta',
        },
        {
            id: 'macro',
            label: 'Macroeconomia',
            icon: 'bar-chart-3',
            placeholder: 'Em breve: ibge_municipio, bcb_indicadores',
        },
    ];

    // Map service_name → tier (para fallback baseado em service_name quando a categoria
    // estática não tem um transform correspondente).
    const SERVICE_TIERS = {
        abuseipdb: 'registered',
        urlscan: 'registered',
        hibp: 'registered',
        emailrep: 'registered',
        hunter: 'registered',
        shodan: 'commercial',
        virustotal: 'commercial',
        securitytrails: 'commercial',
    };

    // State
    const state = {
        // [{ name, display_name, input_types, description, service_name, service_display, _inputTypes }]
        transforms: [],
        fuse: null,
        selectedName: null,
        // Categorias expandidas por padrão (DNS e Identidade — onde estão
        // os transforms mais usados no fluxo de investigação OSINT).
        expandedCategories: new Set(['dns', 'identidade']),
    };

    // ─────────────────────────────────────────────────────────────────────
    // Build transforms list by calling OpenMAPI per known entity type
    // ─────────────────────────────────────────────────────────────────────

    async function fetchAllTransforms() {
        if (!window.OpenMAPI || !window.OpenMAPI.listTransforms) return [];
        // Lista todos os entity types conhecidos (do OpenMAPI, se existir; senão hardcoded).
        const entityTypes = ['Domain', 'IPAddress', 'URL', 'Email', 'Person', 'Device', 'BankAccount', 'MACAddress'];
        const seen = new Set();
        const all = [];
        for (const type of entityTypes) {
            try {
                const data = await window.OpenMAPI.listTransforms(type);
                for (const t of (data.transforms || [])) {
                    if (!seen.has(t.name)) {
                        seen.add(t.name);
                        all.push({ ...t, _inputTypes: t.input_types || [] });
                    }
                }
            } catch (e) {
                // Ignore individual failures; backend may not have a type.
            }
        }
        return all;
    }

    /**
     * Classifica um transform em uma (categoria, tier).
     * Prioriza a categoria/tier declarados estaticamente em CATEGORIES;
     * se não encontrar, faz fallback por service_name.
     */
    function categorizeTransform(t) {
        for (const cat of CATEGORIES) {
            if (cat.placeholder) continue;
            const tiers = cat.serviceTiers || {};
            for (const tier of Object.keys(tiers)) {
                if (tiers[tier].includes(t.name)) return { category: cat, tier };
            }
        }
        // Fallback: classifica por service_name
        if (t.service_name && SERVICE_TIERS[t.service_name]) {
            return { category: CATEGORIES[0], tier: SERVICE_TIERS[t.service_name] }; // DNS genérico
        }
        return { category: CATEGORIES[0], tier: 'free' };
    }

    // ─────────────────────────────────────────────────────────────────────
    // Render tree
    // ─────────────────────────────────────────────────────────────────────

    function getTierIcon(tier) {
        return tier === 'commercial' ? 'lock' : tier === 'registered' ? 'key' : 'zap';
    }

    function renderTree() {
        const tree = document.getElementById('th-tree');
        if (!tree) return;
        tree.innerHTML = '';

        // Group transforms by category
        const groups = CATEGORIES.map((cat) => {
            if (cat.placeholder) {
                return { cat, transforms: [], placeholder: true };
            }
            const transforms = state.transforms
                .map((t) => ({ ...t, _cat: categorizeTransform(t) }))
                .filter((t) => t._cat.category.id === cat.id)
                .map((t) => ({ ...t, _tier: t._cat.tier }));
            return { cat, transforms, placeholder: false };
        });

        groups.forEach((g) => {
            const isExpanded = state.expandedCategories.has(g.cat.id);
            const count = g.placeholder ? '0' : g.transforms.length;

            // Categoria
            const catEl = document.createElement('div');
            catEl.className = 'th-cat';
            catEl.setAttribute('role', 'treeitem');
            catEl.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
            catEl.setAttribute('tabindex', '0');
            catEl.dataset.category = g.cat.id;
            catEl.innerHTML = `
                <i data-lucide="chevron-right" class="th-cat-chevron" aria-hidden="true"></i>
                <i data-lucide="${g.cat.icon}" class="th-node-icon" aria-hidden="true"></i>
                <span class="th-cat-label">${escapeHtml(g.cat.label)}</span>
                <span class="th-cat-count">${count}</span>
            `;
            catEl.addEventListener('click', () => toggleCategory(g.cat.id));
            catEl.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleCategory(g.cat.id);
                }
            });
            tree.appendChild(catEl);

            // Children
            const childrenEl = document.createElement('div');
            childrenEl.className = 'th-cat-children';
            childrenEl.setAttribute('role', 'group');
            if (!isExpanded) childrenEl.style.display = 'none';
            if (g.placeholder) {
                const ph = document.createElement('div');
                ph.className = 'th-node th-node-placeholder';
                ph.style.opacity = '0.5';
                ph.style.fontStyle = 'italic';
                ph.innerHTML = `<i data-lucide="clock" class="th-node-icon" aria-hidden="true"></i><span class="th-node-label">${escapeHtml(g.cat.placeholder)}</span>`;
                childrenEl.appendChild(ph);
            } else {
                g.transforms.forEach((t) => {
                    const nodeEl = createTransformNode(t);
                    childrenEl.appendChild(nodeEl);
                });
            }
            tree.appendChild(childrenEl);
        });

        // Re-render Lucide icons (since we just created new <i data-lucide>)
        if (window.lucide && window.lucide.createIcons) {
            window.lucide.createIcons();
        }
    }

    function createTransformNode(t) {
        const nodeEl = document.createElement('div');
        nodeEl.className = 'th-node';
        nodeEl.setAttribute('role', 'treeitem');
        nodeEl.setAttribute('tabindex', '0');
        nodeEl.dataset.transformName = t.name;
        const tier = t._tier || categorizeTransform(t).tier;
        const icon = getTierIcon(tier);
        nodeEl.innerHTML = `
            <i data-lucide="${icon}" class="th-node-icon" aria-hidden="true"></i>
            <span class="th-node-label">${escapeHtml(t.display_name || t.name)}</span>
            <span class="th-badge th-badge-${tier}">${tier}</span>
        `;
        if (state.selectedName === t.name) nodeEl.classList.add('active');
        nodeEl.addEventListener('click', () => selectTransform(t));
        nodeEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                selectTransform(t);
            }
        });
        return nodeEl;
    }

    function toggleCategory(catId) {
        if (state.expandedCategories.has(catId)) {
            state.expandedCategories.delete(catId);
        } else {
            state.expandedCategories.add(catId);
        }
        renderTree();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Detail panel
    // ─────────────────────────────────────────────────────────────────────

    function selectTransform(t) {
        state.selectedName = t.name;
        // Update active state in tree
        document.querySelectorAll('.th-node').forEach((n) => n.classList.remove('active'));
        const activeNode = document.querySelector(`.th-node[data-transform-name="${cssEscape(t.name)}"]`);
        if (activeNode) activeNode.classList.add('active');

        const detail = document.getElementById('th-detail');
        if (!detail) return;
        const tier = categorizeTransform(t).tier;
        const inputs = (t._inputTypes || t.input_types || []).join(', ');
        const serviceBadge = t.service_name
            ? `<span class="th-badge th-badge-${tier}">${tier}</span>`
            : `<span class="th-badge th-badge-free">free</span>`;
        const runDisabled = !window.Graph || !window.Graph.selected || !window.Graph.selected.isNode || !window.Graph.selected.isNode();
        let runHint;
        if (runDisabled) {
            runHint = '<small>Selecione um node no grafo para rodar este transform.</small>';
        } else {
            const sel = window.Graph.selected;
            const label = (sel.data && sel.data().label) || sel.id();
            runHint = `<small>Será executado em <code>${escapeHtml(label)}</code>.</small>`;
        }

        detail.innerHTML = `
            <div class="th-detail-content">
                <div class="th-detail-header">
                    <h4 class="th-detail-name">${escapeHtml(t.display_name || t.name)}</h4>
                    <div class="th-detail-badge">${serviceBadge}</div>
                </div>
                <p class="th-detail-desc">${escapeHtml(t.description || 'Sem descrição disponível.')}</p>
                <div class="th-detail-meta">
                    <div class="th-detail-meta-row">
                        <span class="th-detail-meta-key">Nome</span>
                        <span class="th-detail-meta-value">${escapeHtml(t.name)}</span>
                    </div>
                    <div class="th-detail-meta-row">
                        <span class="th-detail-meta-key">Inputs</span>
                        <span class="th-detail-meta-value">${escapeHtml(inputs || '—')}</span>
                    </div>
                    <div class="th-detail-meta-row">
                        <span class="th-detail-meta-key">Serviço</span>
                        <span class="th-detail-meta-value">${escapeHtml(t.service_display || t.service_name || 'Nenhum (puro OpenM)')}</span>
                    </div>
                </div>
                <button class="btn primary th-detail-run-btn" id="th-run-btn" ${runDisabled ? 'disabled' : ''}>
                    <i data-lucide="play" aria-hidden="true"></i>
                    Rodar em seleção
                </button>
                <div class="th-detail-hint">${runHint}</div>
            </div>
        `;
        if (window.lucide && window.lucide.createIcons) window.lucide.createIcons();
        const runBtn = document.getElementById('th-run-btn');
        if (runBtn && !runDisabled) {
            runBtn.addEventListener('click', () => runSelectedTransform(t));
        }
        if (window.App && window.App.announce) {
            window.App.announce(`Transform ${t.display_name || t.name} selecionado`, 'polite');
        }
    }

    function runSelectedTransform(t) {
        if (!window.Graph || !window.Graph.selected) {
            if (window.App && window.App.announce) {
                window.App.announce('Selecione um node no grafo antes de rodar o transform', 'assertive');
            }
            return;
        }
        const node = window.Graph.selected;
        if (!node.isNode || !node.isNode()) {
            if (window.App && window.App.announce) {
                window.App.announce('Apenas nodes (não arestas) podem rodar transforms', 'assertive');
            }
            return;
        }
        if (window.App && typeof window.App.runTransform === 'function') {
            // App.runTransform(node, transformName) — node = data() do cytoscape.
            window.App.runTransform(node.data(), t.name);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Search (Fuse.js)
    // ─────────────────────────────────────────────────────────────────────

    function rebuildFuse() {
        if (!window.Fuse) return;
        const data = state.transforms.map((t) => ({
            name: t.name,
            display_name: t.display_name || t.name,
            description: t.description || '',
            service_name: t.service_name || '',
            input_types: (t._inputTypes || []).join(' '),
        }));
        state.fuse = new window.Fuse(data, {
            keys: ['display_name', 'name', 'description', 'input_types'],
            threshold: 0.4,
            ignoreLocation: true,
            minMatchCharLength: 2,
        });
    }

    function onSearchInput(e) {
        const query = e.target.value.trim();
        if (!query || !state.fuse) {
            renderTree();
            return;
        }
        const results = state.fuse.search(query);
        const matchedNames = new Set(results.map((r) => r.item.name));
        // Show all categories expanded, with only matching transforms
        const tree = document.getElementById('th-tree');
        if (!tree) return;
        tree.innerHTML = '';
        let anyShown = false;
        CATEGORIES.forEach((cat) => {
            if (cat.placeholder) return;
            const catTransforms = state.transforms.filter(
                (t) => categorizeTransform(t).category.id === cat.id && matchedNames.has(t.name),
            );
            if (catTransforms.length === 0) return;
            anyShown = true;

            const catEl = document.createElement('div');
            catEl.className = 'th-cat';
            catEl.setAttribute('role', 'treeitem');
            catEl.setAttribute('aria-expanded', 'true');
            catEl.setAttribute('tabindex', '0');
            catEl.dataset.category = cat.id;
            catEl.innerHTML = `
                <i data-lucide="chevron-right" class="th-cat-chevron" style="transform: rotate(90deg)" aria-hidden="true"></i>
                <i data-lucide="${cat.icon}" class="th-node-icon" aria-hidden="true"></i>
                <span class="th-cat-label">${escapeHtml(cat.label)}</span>
                <span class="th-cat-count">${catTransforms.length}</span>
            `;
            tree.appendChild(catEl);

            const childrenEl = document.createElement('div');
            childrenEl.className = 'th-cat-children';
            childrenEl.setAttribute('role', 'group');
            catTransforms.forEach((t) => {
                childrenEl.appendChild(createTransformNode(t));
            });
            tree.appendChild(childrenEl);
        });
        if (!anyShown) {
            const empty = document.createElement('div');
            empty.className = 'th-empty';
            empty.style.padding = '1rem';
            empty.style.opacity = '0.6';
            empty.style.fontStyle = 'italic';
            empty.textContent = `Nenhum transform encontrado para "${query}".`;
            tree.appendChild(empty);
        }
        if (window.lucide && window.lucide.createIcons) window.lucide.createIcons();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Graph event listeners (refresh detail hint when selection changes)
    // ─────────────────────────────────────────────────────────────────────

    function bindGraphEvents() {
        if (!window.cy) return;
        window.cy.on('select unselect', () => {
            // If a transform is selected, refresh the detail to update run-disabled state
            if (state.selectedName) {
                const t = state.transforms.find((x) => x.name === state.selectedName);
                if (t) selectTransform(t);
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────

    function escapeHtml(s) {
        if (s === null || s === undefined) return '';
        return String(s).replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        }[c]));
    }

    /**
     * CSS.escape polyfill simples (suficiente para nomes de transforms que
     * são identificadores snake_case; o caso geral é coberto pelo
     * CSS.escape nativo se disponível).
     */
    function cssEscape(s) {
        if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(s);
        return String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => `\\${c}`);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────

    async function init() {
        // Render placeholder tree (vazio até o fetch terminar)
        renderTree();
        // Bind search
        const searchInput = document.getElementById('th-search');
        if (searchInput) {
            searchInput.addEventListener('input', onSearchInput);
        }
        // Bind graph events
        bindGraphEvents();
        // Fetch transforms (async, may take a moment)
        try {
            state.transforms = await fetchAllTransforms();
            rebuildFuse();
            renderTree();
        } catch (e) {
            console.error('TransformHub: failed to load transforms', e);
        }
        // Re-render Lucide
        if (window.lucide && window.lucide.createIcons) window.lucide.createIcons();
    }

    // Refresh detail when selection changes via global event
    function refresh() {
        if (state.selectedName) {
            const t = state.transforms.find((x) => x.name === state.selectedName);
            if (t) selectTransform(t);
        }
    }

    // Re-render tree (e.g., after category expansion state changes from outside)
    function rerender() {
        renderTree();
    }

    // Run last selected transform (for Cmd+Shift+R)
    function runLastTransform() {
        if (!state.selectedName) {
            if (window.App && window.App.announce) {
                window.App.announce('Nenhum transform selecionado', 'assertive');
            }
            return;
        }
        const t = state.transforms.find((x) => x.name === state.selectedName);
        if (t) runSelectedTransform(t);
    }

    window.TransformHub = { init, refresh, rerender, runLastTransform, getState: () => state };
})();
