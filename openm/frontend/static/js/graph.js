/**
 * Graph - inicialização e manipulação do Cytoscape.js.
 *
 * Recursos estilo Maltego:
 *  - Nós com ícones Font Awesome
 *  - Cores por tipo de entidade
 *  - Drag-and-drop para criar arestas (edgehandles)
 *  - Context menu (botão direito)
 *  - Undo/Redo via pilha de ações
 *  - Subgrafo/centralidade
 */

// Registra plugins do Cytoscape.
if (typeof cytoscape !== 'undefined') {
    if (typeof cytoscapeCoseBilkent !== 'undefined') cytoscape.use(cytoscapeCoseBilkent);
    if (typeof cytoscapeFcose !== 'undefined') cytoscape.use(cytoscapeFcose);
    if (typeof cytoscapeCxtmenu !== 'undefined') cytoscape.use(cytoscapeCxtmenu);
    if (typeof cytoscapeEdgehandles !== 'undefined') cytoscape.use(cytoscapeEdgehandles);
    if (typeof cytoscapeNavigator !== 'undefined') cytoscape.use(cytoscapeNavigator);
}

// Issue #123: feature-detect WebGL2/WebGL para opt-in via localStorage.
// Default OFF — risco Safari 15.4 + bug com background-image SVG inline.
function _supportsWebGL2() {
    try {
        const c = document.createElement('canvas');
        return !!(c.getContext('webgl2') || c.getContext('webgl'));
    } catch (_) {
        return false;
    }
}

let cy = null;
let eh = null;
const undoStack = [];
const redoStack = [];

const Graph = {
    selected: null,
    _layoutEngine: 'cose-bilkent', // Issue #123: 'cose-bilkent' (default) | 'fcose'
    _navigator: null,              // Cytoscape Navigator instance (issue #123)

    init(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return null;

        // Issue #123: WebGL opt-in. Default OFF — usuário habilita via
        // localStorage.setItem('openm:webgl','on'). Bloqueado em Safari 15.0-15.3
        // por bug conhecido com background-image SVG inline.
        const useWebGL = _supportsWebGL2()
            && (typeof localStorage !== 'undefined'
                && localStorage.getItem('openm:webgl') === 'on')
            && !/Safari.*15\.[0-3]/.test(navigator.userAgent || '');

        cy = cytoscape({
            container: container,
            minZoom: 0.2,
            maxZoom: 3,
            wheelSensitivity: 0.2,
            boxSelectionEnabled: true,
            style: this._buildStyle(),
            // Issue #123: opt-in WebGL renderer; default é canvas para compatibilidade.
            renderer: { name: 'canvas', webgl: useWebGL },
        });

        this._initEdgehandles();
        this._initContextMenu();
        this._initEvents();
        this._initNavigator();   // Issue #123: mini-mapa
        this._initKeyboardNav(); // Issue #123: shortcuts +/-, setas, 0

        window.cy = cy;
        window.dispatchEvent(new CustomEvent('graph-ready'));

        // Issue #128: WCAG 2.2 AA — keyboard navigation em Cytoscape
        // Tab cicla entre nodes na ordem de ID, Enter move foco para inspector.
        // Esc clear selection (já existe no listener global em _initEvents).
        const cyContainer = document.getElementById('cy');
        if (cyContainer) {
            cyContainer.addEventListener('keydown', (e) => {
                // Só intercepta se o foco está no canvas
                if (document.activeElement !== cyContainer) return;

                if (e.key === 'Tab') {
                    e.preventDefault();
                    // Coletar nodes em ordem alfabética de ID
                    const allNodes = cy.nodes().sort((a, b) => a.id().localeCompare(b.id()));
                    if (allNodes.length === 0) return;
                    const currentId = this.selected ? this.selected.id() : null;
                    let nextIdx = 0;
                    if (currentId) {
                        const currentIdx = allNodes.findIndex(n => n.id() === currentId);
                        nextIdx = e.shiftKey
                            ? (currentIdx - 1 + allNodes.length) % allNodes.length
                            : (currentIdx + 1) % allNodes.length;
                    }
                    const nextNode = allNodes[nextIdx];
                    if (nextNode) {
                        this.selectNode(nextNode.id());
                        this.announceSelection(nextNode);
                    }
                } else if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    if (this.selected) {
                        // Move foco para o inspector (que tem tabindex="-1" e id="inspector-content")
                        const inspector = document.getElementById('inspector-content');
                        if (inspector) {
                            inspector.focus();
                            window.App && window.App.announce &&
                                window.App.announce('Detalhes do nó abertos no inspector', 'polite');
                        }
                    }
                }
            });
        }

        return cy;
    },

    _buildStyle() {
        const styles = [
            {
                selector: 'node',
                style: {
                    'shape': 'round-rectangle',
                    'background-color': (ele) => getIconBackground(ele.data('type')),
                    'background-opacity': 0.15,
                    'border-width': 2,
                    'border-color': (ele) => getIconBackground(ele.data('type')),
                    'label': 'data(label)',
                    'color': '#e2e8f0',
                    'font-family': 'Inter, sans-serif',
                    'font-size': '11px',
                    'font-weight': 600,
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 6,
                    'text-background-color': '#0a0e1a',
                    'text-background-opacity': 0.9,
                    'text-background-padding': '3px',
                    'text-border-color': '#2a3148',
                    'text-border-width': 1,
                    'text-border-radius': 3,
                    'width': 50,
                    'height': 50,
                    'background-image': (ele) => {
                        // Renderiza o ícone como texto central (FA unicode)
                        const type = ele.data('type');
                        const meta = getEntityMeta(type);
                        // Mapeamento simples de ícones FA para glyphs textuais visíveis
                        const glyphs = {
                            'fa-globe': '◉',
                            'fa-network-wired': '⌘',
                            'fa-envelope': '✉',
                            'fa-user': '☻',
                            'fa-credit-card': '₪',
                            'fa-laptop': '▣',
                        };
                        const glyph = glyphs[meta.icon] || '●';
                        const color = meta.color;
                        return `data:image/svg+xml;utf8,${encodeURIComponent(`
                            <svg xmlns="http://www.w3.org/2000/svg" width="50" height="50" viewBox="0 0 50 50">
                                <text x="25" y="32" font-family="Arial, sans-serif" font-size="22" font-weight="bold"
                                      text-anchor="middle" fill="${color}">${glyph}</text>
                            </svg>
                        `)}`;
                    },
                    'background-fit': 'contain',
                    'background-width': '60%',
                    'background-height': '60%',
                    'background-position-x': '50%',
                    'background-position-y': '40%',
                },
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 3,
                    'border-color': '#f472b6',
                    'background-opacity': 0.3,
                },
            },
            {
                // Issue #6: nó enriquecido por VirusTotal com
                // virustotal_flagged === true ganha borda vermelha e badge.
                selector: 'node[virustotal_flagged = "true"], node[virustotal_flagged = true]',
                style: {
                    'border-width': 3,
                    'border-color': (ele) => getFlaggedColor(),
                    'border-style': 'solid',
                    'background-color': (ele) => getFlaggedColor(),
                    'background-opacity': 0.25,
                    'underlay-color': (ele) => getFlaggedColor(),
                    'underlay-opacity': 0.35,
                    'underlay-padding': 4,
                },
            },
            {
                // Issue #131: nó que casa com a busca fuzzy (Fuse.js)
                // ganha borda accent cyan para destaque visual.
                selector: 'node.cy-node-match',
                style: {
                    'border-width': 3,
                    'border-color': '#38bdf8',
                    'border-style': 'solid',
                    'border-opacity': 1,
                },
            },
            {
                selector: 'node.dimmed',
                style: { 'opacity': 0.25 },
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#475569',
                    'target-arrow-color': '#475569',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'label': 'data(label)',
                    'font-size': '9px',
                    'font-weight': 600,
                    'color': '#94a3b8',
                    'text-rotation': 'autorotate',
                    'text-background-color': '#0a0e1a',
                    'text-background-opacity': 0.9,
                    'text-background-padding': '2px',
                    'text-background-shape': 'rectangle',
                    'text-border-color': '#2a3148',
                    'text-border-width': 1,
                    'text-border-radius': 2,
                },
            },
            {
                selector: 'edge:selected',
                style: {
                    'line-color': '#f472b6',
                    'target-arrow-color': '#f472b6',
                    'width': 3,
                },
            },
        ];
        return styles;
    },

    _initEdgehandles() {
        // edgehandles 2.x: usa callback `complete` em vez de evento `ehcomplete`.
        eh = cy.edgehandles({
            snap: true,
            snapThreshold: 50,
            snapFrequency: 15,
            noEdgeEventsInDraw: false,
            disableBrowserGestures: true,
            canConnect: (source, target) => source.id() !== target.id(),
            complete: (sourceNode, targetNodes, addedEdges) => {
                const targetNode = targetNodes[0];
                if (!targetNode) {
                    if (addedEdges && addedEdges.length) addedEdges.forEach(e => e.remove());
                    return;
                }
                const addedEdge = addedEdges && addedEdges[0];
                if (!addedEdge) return;

                Modal.createEdge({
                    fromNode: sourceNode.data(),
                    toNode: targetNode.data(),
                    onCreate: async ({ rel_type, properties }) => {
                        addedEdge.data('label', rel_type);
                        addedEdge.data('id', `edge-${sourceNode.id()}-${targetNode.id()}-${rel_type}-${Date.now()}`);

                        try {
                            await OpenMAPI.createEdge({
                                from_id: sourceNode.id(),
                                to_id: targetNode.id(),
                                rel_type,
                                properties,
                            });
                            App.setStatus(`Vínculo ${rel_type} criado.`, 'success');
                            this.pushUndo({
                                type: 'add_edge',
                                data: { id: addedEdge.id(), source: sourceNode.id(), target: targetNode.id(), label: rel_type },
                            });
                        } catch (err) {
                            addedEdge.remove();
                            App.setStatus(`Erro ao criar vínculo: ${err.message}`, 'error');
                        }
                    },
                });
            },
        });
    },

    _initContextMenu() {
        cy.cxtmenu({
            selector: 'node',
            commands: [
                {
                    content: '<i class="fa-solid fa-play"></i> Run Transform',
                    select: (ele) => {
                        Inspector.showNode(ele.data());
                    },
                },
                {
                    content: '<i class="fa-solid fa-bolt"></i> Run all transforms',
                    select: (ele) => {
                        App.runAllTransforms(ele.data());
                    },
                },
                {
                    content: '<i class="fa-solid fa-star"></i> Set as Root',
                    select: (ele) => {
                        this.setRoot(ele.id());
                    },
                },
                {
                    content: '<i class="fa-solid fa-link"></i> Start link',
                    select: (ele) => {
                        eh.start(ele);
                    },
                },
                { content: '---' },
                {
                    content: '<i class="fa-solid fa-pen"></i> Edit properties',
                    select: (ele) => {
                        Inspector.showNode(ele.data());
                        setTimeout(() => {
                            document.getElementById('edit-props')?.click();
                        }, 100);
                    },
                },
                {
                    content: '<i class="fa-solid fa-copy"></i> Copy value',
                    select: (ele) => {
                        navigator.clipboard.writeText(ele.data('label') || ele.data('value') || '');
                        App.setStatus('Valor copiado.', 'success');
                    },
                },
                { content: '---' },
                {
                    content: '<i class="fa-solid fa-trash"></i> Delete',
                    select: (ele) => {
                        Modal.confirm({
                            title: 'Remover entidade?',
                            message: `Remover "${ele.data('label')}" e todos os seus vínculos?`,
                            danger: true,
                            onConfirm: () => App.deleteNode(ele.id()),
                        });
                    },
                },
            ],
        });

        cy.cxtmenu({
            selector: 'edge',
            commands: [
                {
                    content: '<i class="fa-solid fa-trash"></i> Delete edge',
                    select: (ele) => {
                        App.deleteEdge(ele.id());
                    },
                },
            ],
        });

        // Background cxtmenu
        cy.cxtmenu({
            selector: 'core',
            commands: [
                {
                    content: '<i class="fa-solid fa-plus"></i> Add entity here',
                    select: (event) => {
                        const pos = event.position || event.cyPosition;
                        if (!pos) return;
                        Modal.createEntity({
                            onCreate: ({ type, value }) => App.createEntity(type, value, { x: pos.x, y: pos.y }),
                        });
                    },
                },
                {
                    content: '<i class="fa-solid fa-expand"></i> Fit to screen',
                    select: () => this.fit(),
                },
                {
                    content: '<i class="fa-solid fa-diagram-project"></i> Re-layout',
                    select: () => this.relayout(),
                },
            ],
        });
    },

    _initEvents() {
        cy.on('tap', 'node', (evt) => {
            this.selected = evt.target;
            this._highlightNeighborhood(evt.target);
            Inspector.showNode(evt.target.data());
        });

        cy.on('tap', 'edge', (evt) => {
            this.selected = evt.target;
            Inspector.showEdge(evt.target.data());
        });

        cy.on('tap', (evt) => {
            if (evt.target === cy) {
                this.selected = null;
                this._clearHighlight();
                Inspector.showEmpty();
            }
        });

        cy.on('zoom', () => this._updateZoomInfo());
        cy.on('pan', () => this._updateZoomInfo());

        // Após qualquer adição, atualiza contagem
        cy.on('add', () => this._updateCount());

        // Hooks para auto-save (issue #28): qualquer mudança no grafo
        // marca como dirty, pra ser salva no próximo tick de AutoSave.
        // Não disparamos em eventos sintéticos (clear, importJson) — esses
        // manipulam _suppressDirty.
        const onChange = () => {
            if (this._suppressDirty) return;
            if (window.AutoSave) window.AutoSave.markDirty();
        };
        cy.on('add', onChange);
        cy.on('remove', onChange);
        cy.on('data', onChange);

        // ESC limpa seleção
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.selected) {
                this.selected.unselect();
                this.selected = null;
                window.App && window.App.announce && window.App.announce('Seleção limpa', 'polite');
                Inspector.showEmpty();
            }
        });
    },

    _highlightNeighborhood(node) {
        this._clearHighlight();
        const neighborhood = node.closedNeighborhood();
        cy.elements().not(neighborhood).addClass('dimmed');
    },

    _clearHighlight() {
        cy.elements().removeClass('dimmed');
    },

    _updateZoomInfo() {
        const el = document.getElementById('zoom-level');
        if (el) el.textContent = `${Math.round(cy.zoom() * 100)}%`;
    },

    _updateCount() {
        const el = document.getElementById('node-count');
        if (el) el.textContent = cy.nodes().length;
    },

    /**
     * Adiciona elementos ao grafo (com dedupe).
     */
    addElements(elements) {
        if (!cy || !elements) return;

        const existingNodeIds = new Set(cy.nodes().map(n => n.id()));
        const existingEdgeIds = new Set(cy.edges().map(e => e.id()));

        // Mapa id -> existe no batch? Usado pra filtrar edges que referenciam
        // nodes que não existem (nem em cy nem no batch — provavelmente dado
        // corrompido do backend).
        const batchNodeIds = new Set();

        const newNodes = (elements.nodes || [])
            .filter(n => n?.data?.id && !existingNodeIds.has(n.data.id))
            .map(n => {
                batchNodeIds.add(n.data.id);
                return { group: 'nodes', data: n.data };
            });

        // Prepara edges SEM verificar se source/target existem (eles serão
        // adicionados junto com os nodes logo abaixo).
        const candidateEdges = (elements.edges || [])
            .filter(e => {
                if (!e?.data) return false;
                const src = e.data.source;
                const tgt = e.data.target;
                if (!src || !tgt) return false;
                if (typeof src !== 'string' || typeof tgt !== 'string') return false;
                if (src === tgt) return false;
                if (existingEdgeIds.has(e.data.id)) return false;
                return true;
            })
            .map(e => {
                const safe = {
                    id: e.data.id,
                    source: e.data.source,
                    target: e.data.target,
                    label: e.data.label,
                };
                for (const [k, v] of Object.entries(e.data)) {
                    if (!['id', 'source', 'target', 'label'].includes(k)) {
                        safe[k] = v;
                    }
                }
                if (!safe.id) {
                    safe.id = `edge-${safe.source}-${safe.target}-${safe.label || 'rel'}-${Date.now()}`;
                }
                return { group: 'edges', data: safe };
            })
            // Filtra edges que apontam pra nodes que não existem nem em cy
            // nem no batch. Cytoscape não rejeita essas edges graciosamente —
            // emite warning e não cria a edge, mas polui o console.
            .filter(e => {
                const srcExists = existingNodeIds.has(e.data.source) || batchNodeIds.has(e.data.source);
                const tgtExists = existingNodeIds.has(e.data.target) || batchNodeIds.has(e.data.target);
                return srcExists && tgtExists;
            });

        if (newNodes.length === 0 && candidateEdges.length === 0) return;

        cy.add([...newNodes, ...candidateEdges]);
        this.relayout();
    },

    addNode(cyData, position) {
        if (!cy) return null;
        const existing = cy.getElementById(cyData.id);
        if (existing.length) {
            existing.data(cyData);
            return existing;
        }
        const node = cy.add({ group: 'nodes', data: cyData });
        if (position) {
            node.position(position);
        }
        this.relayout();
        return node;
    },

    addEdge(id, source, target, label, properties) {
        if (!cy) return null;
        const existing = cy.getElementById(id);
        if (existing.length) return existing;
        const data = { id, source, target, label };
        // Mescla properties extras sem sobrescrever chaves reservadas
        if (properties) {
            for (const [k, v] of Object.entries(properties)) {
                if (!['id', 'source', 'target', 'label'].includes(k)) {
                    data[k] = v;
                }
            }
        }
        const edge = cy.add({ group: 'edges', data });
        return edge;
    },

    selectNode(id) {
        if (!cy) return;
        const node = cy.getElementById(id);
        if (node.length) {
            cy.elements().unselect();
            node.select();
            this._highlightNeighborhood(node);
            Inspector.showNode(node.data());
            cy.animate({ center: { eles: node }, duration: 400 });
        }
    },

    setRoot(id) {
        if (!cy) return;
        const node = cy.getElementById(id);
        if (node.length) {
            cy.elements().removeClass('dimmed');
            node.addClass('dimmed'); // marcador visual
            App.setStatus(`Nó ${node.data('label')} definido como root.`, 'success');
        }
    },

    fit() {
        if (!cy || cy.elements().length === 0) return;
        cy.animate({ fit: { eles: cy.elements(), padding: 40 }, duration: 300 });
    },

    relayout() {
        if (!cy) return;
        // Issue #123: switch entre cose-bilkent (default) e fcose via
        // Graph.setLayoutEngine('fcose' | 'cose-bilkent'). Fallback para grid.
        const useFcose = this._layoutEngine === 'fcose';
        const layoutOpts = useFcose
            ? {
                name: 'fcose',
                animate: true,
                randomize: false,
                fit: true,
                padding: 40,
                nodeRepulsion: 6000,
                idealEdgeLength: 120,
                nodeSeparation: 80,
                quality: 'default',
            }
            : {
                name: 'cose-bilkent',
                animate: true,
                randomize: false,
                fit: true,
                padding: 40,
                componentSpacing: 100,
                nodeRepulsion: 600000,
                idealEdgeLength: 120,
            };
        try {
            cy.layout(layoutOpts).run();
        } catch (err) {
            console.warn('Layout falhou, usando grid:', err);
            try {
                cy.layout({ name: 'grid', fit: true, padding: 40 }).run();
            } catch (err2) {
                console.error('Layout grid também falhou:', err2);
            }
        }
    },

    clear() {
        if (!cy) return;
        if (cy.elements().length === 0) return;
        Modal.confirm({
            title: 'Limpar grafo?',
            message: 'Todas as entidades e vínculos serão removidos da tela (não serão apagados do Neo4j).',
            danger: true,
            onConfirm: () => {
                // Suprime markDirty durante a operação em massa
                this._suppressDirty = true;
                cy.elements().remove();
                this._suppressDirty = false;
                if (window.AutoSave) window.AutoSave.stop();
                App.setStatus('Grafo limpo.', 'info');
            },
        });
    },

    getAdjacent(nodeId) {
        if (!cy) return [];
        const node = cy.getElementById(nodeId);
        if (!node.length) return [];
        return node.neighborhood('node').map(n => n.data());
    },

    removeNode(id) {
        if (!cy) return;
        const node = cy.getElementById(id);
        if (node.length) {
            this.pushUndo({ type: 'remove_node', data: { node: node.data(), edges: node.connectedEdges().map(e => e.data()) } });
            node.remove();
        }
    },

    removeEdge(id) {
        if (!cy) return;
        const edge = cy.getElementById(id);
        if (edge.length) {
            this.pushUndo({ type: 'remove_edge', data: edge.data() });
            edge.remove();
        }
    },

    // Undo/Redo
    pushUndo(action) {
        undoStack.push(action);
        if (undoStack.length > 50) undoStack.shift();
        redoStack.length = 0;
    },

    undo() {
        const action = undoStack.pop();
        if (!action) return;
        if (action.type === 'add_edge') {
            const edge = cy.getElementById(action.data.id);
            if (edge.length) edge.remove();
            redoStack.push(action);
        } else if (action.type === 'remove_node') {
            this.addNode(action.data.node);
            action.data.edges.forEach(e => this.addEdge(e.id, e.source, e.target, e.label, e));
            redoStack.push(action);
        } else if (action.type === 'remove_edge') {
            this.addEdge(action.data.id, action.data.source, action.data.target, action.data.label, action.data);
            redoStack.push(action);
        }
        App.setStatus('Ação desfeita.', 'info');
    },

    redo() {
        const action = redoStack.pop();
        if (!action) return;
        if (action.type === 'add_edge') {
            this.addEdge(action.data.id, action.data.source, action.data.target, action.data.label);
            undoStack.push(action);
        } else if (action.type === 'remove_node') {
            this.removeNode(action.data.node.id);
            undoStack.push(action);
        } else if (action.type === 'remove_edge') {
            this.removeEdge(action.data.id);
            undoStack.push(action);
        }
        App.setStatus('Ação refeita.', 'info');
    },

    exportJson() {
        if (!cy) return null;
        const nodes = cy.nodes().map(n => n.data());
        const edges = cy.edges().map(e => e.data());
        return { nodes, edges, exported_at: new Date().toISOString() };
    },

    importJson(data) {
        if (!cy || !data) return;
        this._suppressDirty = true;
        cy.elements().remove();
        const nodes = (data.nodes || []).map(n => ({ group: 'nodes', data: n }));
        const edges = (data.edges || []).map(e => ({ group: 'edges', data: e }));
        cy.add([...nodes, ...edges]);
        this._suppressDirty = false;
        this.relayout();
        App.setStatus(`Importado: ${nodes.length} nós, ${edges.length} arestas.`, 'success');
    },

    /**
     * Carrega um snapshot de investigation no grafo (issue #27).
     * Suporta 2 formatos:
     *   1. { nodes: [...], edges: [...] }  (formato novo, v2)
     *   2. { elements: [{data}, ...] }     (formato legacy do /api/subgraph)
     * Idempotente: limpa antes de adicionar.
     */
    loadSnapshot(snapshot) {
        if (!cy) return;
        this._suppressDirty = true;
        cy.elements().remove();

        if (!snapshot) {
            this._suppressDirty = false;
            return;
        }

        let nodes = [];
        let edges = [];

        if (Array.isArray(snapshot.nodes) || Array.isArray(snapshot.edges)) {
            // Formato v2
            nodes = snapshot.nodes || [];
            edges = snapshot.edges || [];
        } else if (Array.isArray(snapshot.elements)) {
            // Formato legacy: separar nodes de edges
            for (const el of snapshot.elements) {
                if (!el || !el.data) continue;
                if (el.data.source) edges.push(el.data);
                else nodes.push(el.data);
            }
        }

        cy.add([
            ...nodes.map(n => ({ group: 'nodes', data: n })),
            ...edges.map(e => ({ group: 'edges', data: e })),
        ]);

        this._suppressDirty = false;
        // Render inicial: tenta usar posições do snapshot; senão, layout
        const hasPositions = nodes.some(n => n.position);
        if (hasPositions) {
            cy.fit(undefined, 30);
        } else {
            this.relayout();
        }
    },

    /**
     * Announce the currently selected node/edge to screen readers.
     * @param {object} ele — Cytoscape element (node or edge)
     */
    announceSelection(ele) {
        if (!ele || !window.App || typeof window.App.announce !== 'function') return;
        const data = ele.data() || {};
        const label = data.label || data.value || data.id;
        const type = data.type || (ele.isNode && ele.isNode() ? 'nó' : 'aresta');
        const flagged = data.virustotal_flagged ? ' (flagged)' : '';
        window.App.announce(
            `Selecionado: ${label}, tipo ${type}${flagged}`,
            'polite'
        );
    },

    /**
     * Get the BFS neighborhood of a node up to `depth` levels.
     * Issue #131: powers the "show only selected neighborhood" toggle.
     * @param {string} id — node id
     * @param {number} depth — 1, 2, or 3
     * @returns {object} — Cytoscape Collection of matched nodes (incl. root)
     */
    getNeighborhood(id, depth = 1) {
        if (!window.cy) return null;
        const root = window.cy.getElementById(id);
        if (!root || !root.length) return null;
        const maxDepth = Math.max(1, Math.min(3, depth));
        let visited = root.collection();
        let frontier = root;
        for (let d = 0; d < maxDepth; d++) {
            const next = frontier.neighborhood().difference(visited);
            if (!next.length) break;
            visited = visited.union(next);
            frontier = next;
        }
        return visited;
    },

    // ========================================================================
    // Issue #123: novos métodos — Navigator, keyboard, layout switch, PNG export
    // ========================================================================

    /**
     * Inicializa o mini-mapa Cytoscape Navigator.
     * Se o plugin não estiver registrado ou o container não existir, oculta o
     * container (display: none) para não deixar overlay quebrado.
     */
    _initNavigator() {
        const container = document.getElementById('cy-navigator');
        if (!container) return;
        if (!cy || typeof cy.navigator !== 'function') {
            container.style.display = 'none';
            return;
        }
        try {
            this._navigator = cy.navigator({
                container: '#cy-navigator',
                viewLiveFramerate: 0, // desabilita redraw constante (issue #123)
                thumbnailEventFramerate: 30,
                dblClickDelay: 200,
                removeCustomContainer: false,
            });
        } catch (err) {
            console.warn('Navegador falhou ao inicializar:', err);
            container.style.display = 'none';
        }
    },

    /**
     * Atalhos de teclado adicionais no canvas: + / - / setas / 0.
     * - `+` ou `=`: zoom in centrado
     * - `-`: zoom out centrado
     * - `0`: fit
     * - setas: pan em incrementos fixos
     * Issue #123: descoberta rápida sem mouse.
     */
    _initKeyboardNav() {
        const cyContainer = document.getElementById('cy');
        if (!cyContainer || !cy) return;
        cyContainer.addEventListener('keydown', (e) => {
            if (document.activeElement !== cyContainer) return;
            if (e.ctrlKey || e.metaKey || e.altKey) return;
            if (!cy) return;

            const PAN_STEP = 60;
            if (e.key === '+' || e.key === '=') {
                e.preventDefault();
                cy.zoom({ level: cy.zoom() * 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
            } else if (e.key === '-' || e.key === '_') {
                e.preventDefault();
                cy.zoom({ level: cy.zoom() * 0.8, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
            } else if (e.key === '0') {
                e.preventDefault();
                this.fit();
            } else if (e.key === 'ArrowLeft') {
                e.preventDefault();
                cy.panBy({ x: PAN_STEP, y: 0 });
            } else if (e.key === 'ArrowRight') {
                e.preventDefault();
                cy.panBy({ x: -PAN_STEP, y: 0 });
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                cy.panBy({ x: 0, y: PAN_STEP });
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                cy.panBy({ x: 0, y: -PAN_STEP });
            }
        });
    },

    /**
     * Troca o engine de layout. Aceita 'cose-bilkent' (default) ou 'fcose'.
     * Issue #123: fcose é ~2× mais rápido para grafos grandes, mas pode ter
     * resultado visual diferente.
     */
    setLayoutEngine(name) {
        if (name !== 'cose-bilkent' && name !== 'fcose') {
            console.warn('Engine inválido:', name);
            return;
        }
        this._layoutEngine = name;
        const label = name === 'fcose' ? 'fcose (rápido)' : 'cose-bilkent (padrão)';
        if (window.App && typeof window.App.setStatus === 'function') {
            window.App.setStatus(`Layout engine: ${label}.`, 'info');
        }
    },

    /**
     * Exporta o grafo atual como PNG. Usa `output: 'blob-promise'` para
     * não bloquear a thread principal. Padrão de download idêntico ao
     * `App.exportGraph()` (Blob → URL.createObjectURL → <a download> → revoke).
     */
    async exportPng() {
        if (!cy) {
            if (window.App && window.App.setStatus) {
                window.App.setStatus('Grafo não inicializado.', 'error');
            }
            return;
        }
        if (typeof cy.png !== 'function') {
            if (window.App && window.App.setStatus) {
                window.App.setStatus('Export PNG indisponível nesta versão.', 'error');
            }
            return;
        }
        try {
            const blob = await cy.png({
                output: 'blob-promise',
                bg: '#131826', // oklch fallback para bg do canvas (issue #126)
                full: true,
                scale: 2,
                maxWidth: 4096,
                maxHeight: 4096,
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `openm-graph-${Date.now()}.png`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            if (window.App) {
                if (typeof window.App.setStatus === 'function') {
                    window.App.setStatus('PNG exportado.', 'success');
                }
                if (typeof window.App.announce === 'function') {
                    window.App.announce('PNG exportado', 'polite');
                }
            }
        } catch (err) {
            console.error('Falha ao exportar PNG:', err);
            if (window.App && typeof window.App.setStatus === 'function') {
                window.App.setStatus('Falha ao exportar PNG: ' + (err && err.message || err), 'error');
            }
        }
    },

    /**
     * Mostra/oculta o container do mini-mapa via classe .collapsed.
     * O CSS já cuida de opacity/transform/pointer-events.
     */
    setNavigatorVisible(visible) {
        const container = document.getElementById('cy-navigator');
        if (!container) return;
        if (visible) {
            container.classList.remove('collapsed');
        } else {
            container.classList.add('collapsed');
        }
    },
};

window.Graph = Graph;
