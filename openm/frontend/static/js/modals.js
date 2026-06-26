/**
 * Sistema de modais para ações do usuário.
 */

const Modal = {
    open({ title, body, footer, onClose }) {
        const root = document.getElementById('modal-root');
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';

        const modal = document.createElement('div');
        modal.className = 'modal';

        const header = document.createElement('div');
        header.className = 'modal-header';
        header.innerHTML = `<h3>${title}</h3><button class="close">&times;</button>`;
        modal.appendChild(header);

        const bodyEl = document.createElement('div');
        bodyEl.className = 'modal-body';
        if (typeof body === 'string') bodyEl.innerHTML = body;
        else if (body instanceof Node) bodyEl.appendChild(body);
        modal.appendChild(bodyEl);

        if (footer) {
            const footerEl = document.createElement('div');
            footerEl.className = 'modal-footer';
            if (typeof footer === 'string') footerEl.innerHTML = footer;
            else if (footer instanceof Node) footerEl.appendChild(footer);
            modal.appendChild(footerEl);
        }

        backdrop.appendChild(modal);
        root.appendChild(backdrop);

        const close = () => {
            backdrop.remove();
            if (onClose) onClose();
        };

        header.querySelector('.close').addEventListener('click', close);
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) close();
        });

        return { close, modal, bodyEl, backdrop };
    },

    confirm({ title, message, danger = false, onConfirm }) {
        const body = `<p>${message}</p>`;
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        footer.innerHTML = `
            <button class="btn cancel">Cancelar</button>
            <button class="btn ${danger ? 'danger' : 'primary'} confirm">Confirmar</button>
        `;
        const { close, modal } = this.open({ title, body, footer });
        modal.querySelector('.cancel').addEventListener('click', close);
        modal.querySelector('.confirm').addEventListener('click', () => {
            onConfirm && onConfirm();
            close();
        });
    },

    conflictResolve({ currentVersion, yourVersion, currentSnapshot, onReload, onOverwrite, onCancel }) {
        /**
         * Modal para resolver conflito de versão (optimistic locking,
         * issue #37). Disparado quando o PUT recebe 409 — significa que
         * outra aba/user salvou uma versão mais recente.
         *
         * 3 opções:
         * - Cancelar:     fecha modal, mantém local, marca como não salvo
         * - Recarregar:   substitui grafo com current_snapshot do servidor
         * - Sobrescrever: força PUT sem If-Match (atômico do lado servidor)
         */
        const body = document.createElement('div');
        body.innerHTML = `
            <p>
                <strong>Esta investigation foi modificada em outra aba, janela ou por outro usuário.</strong>
            </p>
            <p style="margin-top: 0.8rem;">
                Sua versão: <code>${yourVersion}</code><br>
                Versão atual no servidor: <code>${currentVersion}</code>
            </p>
            <p style="margin-top: 0.8rem; color: var(--text-dim, #888); font-size: 0.9rem;">
                <strong>Recarregar</strong> perde suas alterações locais.<br>
                <strong>Sobrescrever</strong> força sua versão (descarta mudanças do servidor).
            </p>
        `;

        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        footer.style.justifyContent = 'flex-end';
        footer.innerHTML = `
            <button class="btn cancel">Cancelar</button>
            <button class="btn reload">Recarregar</button>
            <button class="btn danger overwrite">Sobrescrever</button>
        `;

        const { close, modal } = this.open({
            title: 'Conflito de versão detectado',
            body,
            footer,
            onClose: () => {
                // Se fechou sem escolher (X ou backdrop), trata como Cancelar
                // — comportamento conservador (preserva mudanças locais).
                if (onCancel) onCancel();
            },
        });

        modal.querySelector('.cancel').addEventListener('click', () => {
            if (onCancel) onCancel();
            close();
        });
        modal.querySelector('.reload').addEventListener('click', () => {
            if (onReload) onReload();
            close();
        });
        modal.querySelector('.overwrite').addEventListener('click', async () => {
            // Desabilita botão enquanto processa (evita duplo clique)
            const btn = modal.querySelector('.overwrite');
            btn.disabled = true;
            btn.textContent = 'Sobrescrevendo...';
            try {
                if (onOverwrite) await onOverwrite();
            } finally {
                close();
            }
        });
    },

    createEdge({ fromNode, toNode, onCreate }) {
        const body = document.createElement('div');
        body.innerHTML = `
            <p style="margin-top:0; color:var(--text-dim); font-size:0.85rem">
                <strong style="color:var(--text)">${fromNode.label || fromNode.value}</strong>
                <i class="fa-solid fa-arrow-right" style="margin:0 0.4rem"></i>
                <strong style="color:var(--text)">${toNode.label || toNode.value}</strong>
            </p>
            <label>Tipo de relação</label>
            <select id="rel-type">
                <option value="OWNS">OWNS (possui)</option>
                <option value="CONNECTED_TO">CONNECTED_TO (conectado a)</option>
                <option value="ASSOCIATED_WITH">ASSOCIATED_WITH (associado a)</option>
                <option value="TRANSACTED_WITH">TRANSACTED_WITH (transacionou com)</option>
                <option value="HOSTED_ON">HOSTED_ON (hospedado em)</option>
                <option value="SUSPICIOUS_LOGIN">SUSPICIOUS_LOGIN (login suspeito)</option>
                <option value="custom">Personalizado...</option>
            </select>
            <label id="custom-rel-label" style="display:none">Nome personalizado</label>
            <input type="text" id="rel-custom" placeholder="EX: PART_OF" style="display:none">
            <label>Notas (opcional)</label>
            <textarea id="rel-notes" rows="2" placeholder="Detalhes do vínculo..."></textarea>
        `;
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        footer.innerHTML = `
            <button class="btn cancel">Cancelar</button>
            <button class="btn primary confirm">Criar Vínculo</button>
        `;
        const { close, modal } = this.open({ title: 'Novo Vínculo', body, footer });

        const sel = modal.querySelector('#rel-type');
        const custom = modal.querySelector('#rel-custom');
        const customLabel = modal.querySelector('#custom-rel-label');
        sel.addEventListener('change', () => {
            if (sel.value === 'custom') {
                custom.style.display = 'block';
                customLabel.style.display = 'block';
            } else {
                custom.style.display = 'none';
                customLabel.style.display = 'none';
            }
        });

        modal.querySelector('.cancel').addEventListener('click', close);
        modal.querySelector('.confirm').addEventListener('click', () => {
            const relType = sel.value === 'custom'
                ? (custom.value || 'CUSTOM').toUpperCase().replace(/\s+/g, '_')
                : sel.value;
            const notes = modal.querySelector('#rel-notes').value.trim();
            onCreate && onCreate({
                rel_type: relType,
                properties: notes ? { notes } : {},
            });
            close();
        });
    },

    createEntity({ initialType, onCreate }) {
        const types = Object.keys(ENTITY_ICONS).filter(t => t !== 'Generic');
        const body = document.createElement('div');
        body.innerHTML = `
            <label>Tipo de Entidade</label>
            <select id="ent-type">
                ${types.map(t => `<option value="${t}" ${t === initialType ? 'selected' : ''}>${t}</option>`).join('')}
            </select>
            <label>Valor</label>
            <input type="text" id="ent-value" placeholder="ex: example.com" autofocus>
        `;
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        footer.innerHTML = `
            <button class="btn cancel">Cancelar</button>
            <button class="btn primary confirm">Criar e Adicionar</button>
        `;
        const { close, modal } = this.open({ title: 'Nova Entidade', body, footer });
        const valueInput = modal.querySelector('#ent-value');
        setTimeout(() => valueInput.focus(), 100);

        modal.querySelector('.cancel').addEventListener('click', close);
        modal.querySelector('.confirm').addEventListener('click', () => {
            const type = modal.querySelector('#ent-type').value;
            const value = valueInput.value.trim();
            if (!value) { valueInput.focus(); return; }
            onCreate && onCreate({ type, value });
            close();
        });
    },

    editProperties({ node, onSave }) {        const body = document.createElement('div');
        const props = Object.entries(node).filter(([k]) =>
            !['id', 'label', 'type', 'value', 'source', 'target'].includes(k)
        );
        body.innerHTML = `
            <p style="margin-top:0; color:var(--text-dim); font-size:0.85rem">
                <strong>${node.label || node.id}</strong>
            </p>
            <div id="props-list">
                ${props.map(([k, v], i) => `
                    <div class="prop-row" style="padding:0.3rem 0">
                        <input type="text" class="prop-k" value="${k}" placeholder="chave" style="width:40%">
                        <input type="text" class="prop-v" value="${typeof v === 'object' ? JSON.stringify(v) : v}" placeholder="valor" style="flex:1">
                        <button class="btn sm danger del-prop" title="Remover"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                `).join('')}
            </div>
            <button class="btn sm" id="add-prop" style="margin-top:0.4rem">
                <i class="fa-solid fa-plus"></i>Adicionar propriedade
            </button>
        `;
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        footer.innerHTML = `
            <button class="btn cancel">Cancelar</button>
            <button class="btn primary confirm">Salvar</button>
        `;
        const { close, modal } = this.open({ title: 'Editar Propriedades', body, footer });

        const list = modal.querySelector('#props-list');
        modal.querySelector('#add-prop').addEventListener('click', () => {
            const row = document.createElement('div');
            row.className = 'prop-row';
            row.style.padding = '0.3rem 0';
            row.innerHTML = `
                <input type="text" class="prop-k" placeholder="chave" style="width:40%">
                <input type="text" class="prop-v" placeholder="valor" style="flex:1">
                <button class="btn sm danger del-prop" title="Remover"><i class="fa-solid fa-xmark"></i></button>
            `;
            list.appendChild(row);
            row.querySelector('.del-prop').addEventListener('click', () => row.remove());
        });

        list.querySelectorAll('.del-prop').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.target.closest('.prop-row').remove();
            });
        });

        modal.querySelector('.cancel').addEventListener('click', close);
        modal.querySelector('.confirm').addEventListener('click', () => {
            const newProps = {};
            modal.querySelectorAll('.prop-row').forEach(row => {
                const k = row.querySelector('.prop-k').value.trim();
                const v = row.querySelector('.prop-v').value.trim();
                if (k) newProps[k] = v;
            });
            onSave && onSave(newProps);
            close();
        });
    },
};

window.Modal = Modal;
