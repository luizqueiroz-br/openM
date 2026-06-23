/**
 * Inspector - painel direito que exibe detalhes do nó/aresta selecionado.
 */

const Inspector = {
    el: null,
    currentSelection: null,
    currentType: null, // 'node' | 'edge'

    init() {
        this.el = document.getElementById('inspector-content');
    },

    showEmpty() {
        this.currentSelection = null;
        this.currentType = null;
        this.el.innerHTML = `
            <div class="inspector-empty">
                <i class="fa-solid fa-circle-info" style="font-size:2rem; margin-bottom:0.5rem; display:block"></i>
                Selecione um nó ou aresta para ver detalhes
            </div>`;
        window.dispatchEvent(new CustomEvent('selection-cleared'));
    },

    showNode(node) {
        this.currentSelection = node;
        this.currentType = 'node';
        const meta = getEntityMeta(node.type);

        const props = Object.entries(node).filter(([k]) =>
            !['id', 'label', 'type'].includes(k)
        );
        const adj = window.Graph.getAdjacent ? window.Graph.getAdjacent(node.id) : [];

        this.el.innerHTML = `
            <div class="inspector-header">
                <div class="icon" style="background:${meta.color}">
                    <i class="fa-solid ${meta.icon}"></i>
                </div>
                <div class="meta">
                    <div class="type">${node.type}</div>
                    <div class="value">${escapeHtml(String(node.label || node.value || node.id))}</div>
                </div>
            </div>
            <div class="inspector-tabs">
                <button class="inspector-tab active" data-tab="props">Propriedades</button>
                <button class="inspector-tab" data-tab="transforms">Transforms</button>
                <button class="inspector-tab" data-tab="adj">Adjacentes</button>
            </div>
            <div class="inspector-body">
                <div class="tab-pane" data-pane="props">
                    <div class="prop-row">
                        <span class="k">ID</span>
                        <span class="v mono">${node.id.substring(0, 8)}…</span>
                    </div>
                    <div class="prop-row">
                        <span class="k">Tipo</span>
                        <span class="v">${node.type}</span>
                    </div>
                    <div class="prop-row">
                        <span class="k">Valor</span>
                        <span class="v mono">${escapeHtml(String(node.label || node.value || ''))}</span>
                    </div>
                    ${props.length === 0 ? '<div class="empty">Sem propriedades extras</div>' : ''}
                    ${props.map(([k, v]) => `
                        <div class="prop-row">
                            <span class="k">${escapeHtml(k)}</span>
                            <span class="v">${escapeHtml(String(typeof v === 'object' ? JSON.stringify(v) : v))}</span>
                        </div>
                    `).join('')}
                    <button class="btn sm" id="edit-props" style="margin-top:0.6rem; width:100%">
                        <i class="fa-solid fa-pen"></i>Editar propriedades
                    </button>
                </div>
                <div class="tab-pane" data-pane="transforms" style="display:none">
                    <div id="transforms-list"></div>
                </div>
                <div class="tab-pane" data-pane="adj" style="display:none">
                    <div class="adj-list" id="adj-list"></div>
                </div>
            </div>
        `;

        // Tabs
        this.el.querySelectorAll('.inspector-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.el.querySelectorAll('.inspector-tab').forEach(t => t.classList.remove('active'));
                this.el.querySelectorAll('.tab-pane').forEach(p => p.style.display = 'none');
                tab.classList.add('active');
                this.el.querySelector(`[data-pane="${tab.dataset.tab}"]`).style.display = 'block';
            });
        });

        // Edit properties
        this.el.querySelector('#edit-props').addEventListener('click', () => {
            Modal.editProperties({
                node,
                onSave: (newProps) => window.App.updateNodeProperties(node.id, newProps),
            });
        });

        // Carrega transforms disponíveis
        this.loadTransforms(node);

        // Carrega adjacentes
        this.loadAdjacent(adj);

        window.dispatchEvent(new CustomEvent('selection-changed', { detail: { node } }));
    },

    showEdge(edge) {
        this.currentSelection = edge;
        this.currentType = 'edge';

        this.el.innerHTML = `
            <div class="inspector-header">
                <div class="icon" style="background:var(--text-faint)">
                    <i class="fa-solid fa-link"></i>
                </div>
                <div class="meta">
                    <div class="type">Vínculo</div>
                    <div class="value mono">${edge.label || 'REL'}</div>
                </div>
            </div>
            <div class="inspector-body">
                <div class="prop-row">
                    <span class="k">ID</span>
                    <span class="v mono">${(edge.id || '').substring(0, 12)}…</span>
                </div>
                <div class="prop-row">
                    <span class="k">De</span>
                    <span class="v mono">${(edge.source || '').substring(0, 8)}…</span>
                </div>
                <div class="prop-row">
                    <span class="k">Para</span>
                    <span class="v mono">${(edge.target || '').substring(0, 8)}…</span>
                </div>
                ${Object.entries(edge).filter(([k]) => !['id','label','source','target'].includes(k))
                    .map(([k, v]) => `
                        <div class="prop-row">
                            <span class="k">${escapeHtml(k)}</span>
                            <span class="v">${escapeHtml(String(typeof v === 'object' ? JSON.stringify(v) : v))}</span>
                        </div>
                    `).join('')}
                <button class="btn danger" id="delete-edge" style="width:100%; margin-top:1rem">
                    <i class="fa-solid fa-trash"></i>Remover vínculo
                </button>
            </div>
        `;

        this.el.querySelector('#delete-edge').addEventListener('click', () => {
            Modal.confirm({
                title: 'Remover vínculo?',
                message: 'Esta ação removerá o vínculo entre as entidades.',
                danger: true,
                onConfirm: () => window.App.deleteEdge(edge.id),
            });
        });
    },

    async loadTransforms(node) {
        const list = this.el.querySelector('#transforms-list');
        list.innerHTML = '<div class="empty">Carregando...</div>';
        try {
            const data = await OpenMAPI.listTransforms(node.type);
            if (!data.transforms || data.transforms.length === 0) {
                list.innerHTML = '<div class="empty">Nenhum transform disponível para este tipo.</div>';
                return;
            }
            list.innerHTML = data.transforms.map(t => `
                <button class="transform-btn" data-name="${t.name}">
                    <i class="fa-solid fa-play"></i>
                    <div>
                        <strong>${escapeHtml(t.display_name)}</strong>
                        <small>${escapeHtml(t.description)}</small>
                    </div>
                </button>
            `).join('');
            list.querySelectorAll('.transform-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    window.App.runTransform(node, btn.dataset.name);
                });
            });
        } catch (err) {
            list.innerHTML = `<div class="empty">Erro: ${err.message}</div>`;
        }
    },

    loadAdjacent(adj) {
        const list = this.el.querySelector('#adj-list');
        if (!adj || adj.length === 0) {
            list.innerHTML = '<div class="empty">Nenhuma entidade adjacente</div>';
            return;
        }
        list.innerHTML = adj.map(a => {
            const meta = getEntityMeta(a.type);
            return `
                <div class="adj-item" data-id="${a.id}">
                    <div class="icon" style="background:${meta.color}">
                        <i class="fa-solid ${meta.icon}"></i>
                    </div>
                    <div style="flex:1; min-width:0">
                        <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap">${escapeHtml(a.label || a.value || a.id)}</div>
                        <div class="meta">${a.type}</div>
                    </div>
                </div>
            `;
        }).join('');
        list.querySelectorAll('.adj-item').forEach(item => {
            item.addEventListener('click', () => {
                window.Graph.selectNode(item.dataset.id);
            });
        });
    },
};

window.Inspector = Inspector;

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
