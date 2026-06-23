/**
 * App - orquestração principal do OpenM.
 */

const App = {
    setStatus(message, type = 'info') {
        const el = document.getElementById('status-msg');
        el.textContent = message;
        if (type === 'error') el.style.color = 'var(--danger)';
        else if (type === 'success') el.style.color = 'var(--success)';
        else el.style.color = 'var(--text-dim)';
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
            const data = await OpenMAPI.listInvestigations();
            const list = document.getElementById('investigations-list');
            if (!list) return;
            if (!data.investigations || data.investigations.length === 0) {
                list.innerHTML = '<li class="empty">Nenhuma investigação</li>';
                return;
            }
            list.innerHTML = data.investigations.map(inv => `
                <li data-root="${inv.root_entity_id || ''}" data-id="${inv.id}">
                    <span class="title">${escapeHtml(inv.title)}</span>
                    <span class="meta">${inv.created_at ? new Date(inv.created_at).toLocaleDateString() : ''}</span>
                </li>
            `).join('');
            list.querySelectorAll('li').forEach(li => {
                if (!li.classList.contains('empty')) {
                    li.addEventListener('click', async () => {
                        const rootId = li.dataset.root;
                        if (!rootId) {
                            this.setStatus('Esta investigação não tem entidade raiz — não pode ser reaberta.', 'error');
                            return;
                        }
                        try {
                            const sub = await OpenMAPI.getSubgraph(rootId, 2);
                            cy.elements().remove();
                            // /api/subgraph pode retornar 2 formatos inconsistentes:
                            //   1. Cytoscape cru: {elements: [{data}, ...]}
                            //   2. Wrapper:        {elements: {nodes: [...], edges: [...]}}
                            // Aceitamos ambos. Graph.addElements espera {nodes, edges}.
                            let raw = [];
                            const el = sub.elements;
                            if (Array.isArray(el)) {
                                raw = el;
                            } else if (el && Array.isArray(el.nodes)) {
                                raw = [...el.nodes, ...(el.edges || [])];
                            }
                            const normalized = {
                                nodes: raw.filter(e => e.data && !e.data.source),
                                edges: raw.filter(e => e.data && e.data.source),
                            };
                            Graph.addElements(normalized);
                            this.setStatus(`Investigação "${li.querySelector('.title')?.textContent || ''}" carregada.`, 'success');
                        } catch (err) {
                            this.setStatus(err.message, 'error');
                        }
                    });
                }
            });
        } catch (err) {
            this.setStatus(err.message, 'error');
        }
    },

    async createInvestigation() {
        const title = document.getElementById('inv-title').value.trim();
        const desc = document.getElementById('inv-desc').value.trim();
        if (!title) {
            this.setStatus('Título é obrigatório', 'error');
            return;
        }
        const rootId = Graph.selected ? Graph.selected.id() : null;
        try {
            const result = await OpenMAPI.createInvestigation(title, desc, rootId);
            const savedTitle = result?.investigation?.title || title;
            const savedRoot = result?.investigation?.root_entity_id;
            if (savedRoot) {
                this.setStatus(`✓ Investigação "${savedTitle}" salva (com entidade raiz — pode ser reaberta).`, 'success');
            } else {
                this.setStatus(`⚠ Investigação "${savedTitle}" salva SEM entidade raiz — não vai poder ser reaberta pelo nome. Selecione um nó antes de salvar para incluir uma raiz.`, 'error');
            }
            document.getElementById('inv-title').value = '';
            document.getElementById('inv-desc').value = '';
            this.loadInvestigations();
        } catch (err) {
            this.setStatus(err.message, 'error');
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
        document.getElementById('btn-save').addEventListener('click', () => this.createInvestigation());
        document.getElementById('btn-export').addEventListener('click', () => this.exportGraph());
        document.getElementById('btn-import').addEventListener('click', () => this.importGraph());

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

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'z' && !e.shiftKey) {
                e.preventDefault();
                Graph.undo();
            } else if ((e.ctrlKey || e.metaKey) && (e.key === 'y' || (e.key === 'z' && e.shiftKey))) {
                e.preventDefault();
                Graph.redo();
            } else if (e.key === 'f' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT') {
                Graph.fit();
            } else if (e.key === 'Delete' && Graph.selected) {
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
        Inspector.init();
        Palette.init();
        Graph.init('cy');
        this.bindTopbar();
        this.loadInvestigations();
        this.loadKeys();
        this.setStatus('Pronto. Arraste entidades da paleta para o canvas.');
        this.loadUser();
    },

    async loadUser() {
        const user = await OpenMAuth.bootstrap();
        if (user) {
            const el = document.getElementById('user-email');
            if (el) el.textContent = user.email;
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
