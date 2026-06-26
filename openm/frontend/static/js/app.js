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
        this.loadKeyServices();
        this.loadKeys();
        this.setStatus('Pronto. Arraste entidades da paleta para o canvas.');
        this.loadUser();
    },

    async loadUser() {
        const user = await OpenMAuth.bootstrap();
        if (user) {
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
