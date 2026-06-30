/**
 * Sistema de modais para ações do usuário.
 *
 * Refactorado (issue #127, parte 2) para usar Web Awesome 3.9+ `<wa-dialog>`
 * como base. Mantém fallback para o markup antigo (`.modal-backdrop` +
 * `.modal`) caso o componente WA ainda não esteja registrado.
 *
 * A API pública de `Modal.*` permanece compatível: callers
 * (`app.js`, `inspector.js`, `palette.js`, `graph.js`) continuam
 * invocando `Modal.confirm`, `Modal.createEntity`, etc. sem alterações.
 */

function _waReady(tag) {
    return typeof window !== 'undefined' && !!window.customElements && !!customElements.get(tag);
}

function _createWaDialog({ title, label }) {
    const root = document.getElementById('modal-root');
    const dialog = document.createElement('wa-dialog');
    dialog.setAttribute('label', label || title || '');
    // light-dismiss → ESC e clique no backdrop fecham (ganho de a11y sobre o código antigo)
    dialog.setAttribute('light-dismiss', '');
    dialog.setAttribute('class', 'wa-modal'); // hook para CSS
    dialog.innerHTML = `
        <div class="wa-modal-header"><h3></h3></div>
        <div class="wa-modal-body"></div>
        <div class="wa-modal-footer" slot="footer"></div>
    `;
    dialog.querySelector('.wa-modal-header h3').textContent = title || label || '';
    root.appendChild(dialog);
    return {
        dialog,
        bodyEl: dialog.querySelector('.wa-modal-body'),
        footerEl: dialog.querySelector('.wa-modal-footer'),
    };
}

function _openWaDialog(dialog) {
    if (typeof dialog.show === 'function') {
        dialog.show();
    } else {
        dialog.setAttribute('open', '');
    }
}

function _closeWaDialog(dialog, instance) {
    const teardown = () => {
        if (instance && instance.onClose) instance.onClose();
        if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
    };
    if (typeof dialog.hide === 'function') {
        // Escutar wa-after-hide uma única vez para desmontar após animação
        dialog.addEventListener('wa-after-hide', teardown, { once: true });
        dialog.hide();
    } else {
        dialog.removeAttribute('open');
        teardown();
    }
}

const Modal = {
    open({ title, body, footer, onClose }) {
        // Fallback: WA <wa-dialog> não registrado → markup legado
        if (!_waReady('wa-dialog')) {
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
        }

        // Caminho Web Awesome
        const { dialog, bodyEl, footerEl } = _createWaDialog({ title, label: title });
        if (typeof body === 'string') bodyEl.innerHTML = body;
        else if (body instanceof Node) bodyEl.appendChild(body);
        if (footer) {
            if (typeof footer === 'string') footerEl.innerHTML = footer;
            else if (footer instanceof Node) footerEl.appendChild(footer);
        }

        const instance = { onClose };
        _openWaDialog(dialog);
        const close = () => _closeWaDialog(dialog, instance);

        // ESC / backdrop click já são tratados por `light-dismiss`,
        // mas precisamos disparar onClose no caminho WA também
        dialog.addEventListener('wa-after-hide', () => {
            if (instance.onClose) {
                instance.onClose();
                instance.onClose = null; // evita disparo duplo via _closeWaDialog
            }
        });

        return { close, modal: dialog, bodyEl, backdrop: dialog };
    },

    confirm({ title, message, danger = false, onConfirm }) {
        const waReady = _waReady('wa-dialog') && _waReady('wa-button');
        const body = `<p>${message}</p>`;
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';

        if (waReady) {
            footer.innerHTML = `
                <wa-button class="cancel" slot="footer" variant="default">Cancelar</wa-button>
                <wa-button class="confirm" slot="footer" variant="${danger ? 'danger' : 'primary'}">Confirmar</wa-button>
            `;
        } else {
            footer.innerHTML = `
                <button class="btn cancel">Cancelar</button>
                <button class="btn ${danger ? 'danger' : 'primary'} confirm">Confirmar</button>
            `;
        }

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
        const waReady = _waReady('wa-dialog') && _waReady('wa-button');
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
        if (waReady) {
            footer.innerHTML = `
                <wa-button class="cancel" slot="footer" variant="default">Cancelar</wa-button>
                <wa-button class="reload" slot="footer" variant="primary">Recarregar</wa-button>
                <wa-button class="overwrite" slot="footer" variant="danger">Sobrescrever</wa-button>
            `;
        } else {
            footer.innerHTML = `
                <button class="btn cancel">Cancelar</button>
                <button class="btn reload">Recarregar</button>
                <button class="btn danger overwrite">Sobrescrever</button>
            `;
        }

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
        const waReady = _waReady('wa-dialog') && _waReady('wa-button')
            && _waReady('wa-select') && _waReady('wa-input') && _waReady('wa-textarea');
        const body = document.createElement('div');
        if (waReady) {
            body.innerHTML = `
                <p style="margin-top:0; color:var(--text-dim); font-size:0.85rem">
                    <strong style="color:var(--text)">${fromNode.label || fromNode.value}</strong>
                    <i class="fa-solid fa-arrow-right" style="margin:0 0.4rem"></i>
                    <strong style="color:var(--text)">${toNode.label || toNode.value}</strong>
                </p>
                <wa-select id="rel-type" label="Tipo de relação">
                    <wa-option value="OWNS">OWNS (possui)</wa-option>
                    <wa-option value="CONNECTED_TO">CONNECTED_TO (conectado a)</wa-option>
                    <wa-option value="ASSOCIATED_WITH">ASSOCIATED_WITH (associado a)</wa-option>
                    <wa-option value="TRANSACTED_WITH">TRANSACTED_WITH (transacionou com)</wa-option>
                    <wa-option value="HOSTED_ON">HOSTED_ON (hospedado em)</wa-option>
                    <wa-option value="SUSPICIOUS_LOGIN">SUSPICIOUS_LOGIN (login suspeito)</wa-option>
                    <wa-option value="custom">Personalizado...</wa-option>
                </wa-select>
                <wa-input id="rel-custom" label="Nome personalizado" placeholder="EX: PART_OF" style="display:none"></wa-input>
                <wa-textarea id="rel-notes" label="Notas (opcional)" rows="2" placeholder="Detalhes do vínculo..."></wa-textarea>
            `;
        } else {
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
        }
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        if (waReady) {
            footer.innerHTML = `
                <wa-button class="cancel" slot="footer" variant="default">Cancelar</wa-button>
                <wa-button class="confirm" slot="footer" variant="primary">Criar Vínculo</wa-button>
            `;
        } else {
            footer.innerHTML = `
                <button class="btn cancel">Cancelar</button>
                <button class="btn primary confirm">Criar Vínculo</button>
            `;
        }
        const { close, modal } = this.open({ title: 'Novo Vínculo', body, footer });

        const sel = modal.querySelector('#rel-type');
        const custom = modal.querySelector('#rel-custom');
        // No WA, o atributo value reflete o `<wa-option value="...">` selecionado
        const onChange = () => {
            const showCustom = sel.value === 'custom';
            custom.style.display = showCustom ? '' : 'none';
        };
        sel.addEventListener('change', onChange);
        // wa-select dispara 'change' via slot/picker — se não rolar,
        // ouvir o evento nativo que o componente emite
        sel.addEventListener('input', onChange);

        modal.querySelector('.cancel').addEventListener('click', close);
        modal.querySelector('.confirm').addEventListener('click', () => {
            // Para wa-input, ler via .value; fallback para input nativo
            const customVal = (custom.value !== undefined ? custom.value : custom.querySelector?.('input')?.value) || '';
            const notesVal = modal.querySelector('#rel-notes').value || '';
            const relType = sel.value === 'custom'
                ? (customVal || 'CUSTOM').toUpperCase().replace(/\s+/g, '_')
                : sel.value;
            const notes = notesVal.trim();
            onCreate && onCreate({
                rel_type: relType,
                properties: notes ? { notes } : {},
            });
            close();
        });
    },

    createEntity({ initialType, onCreate }) {
        const types = Object.keys(ENTITY_ICONS).filter(t => t !== 'Generic');
        const waReady = _waReady('wa-dialog') && _waReady('wa-button')
            && _waReady('wa-select') && _waReady('wa-input');
        const body = document.createElement('div');
        if (waReady) {
            body.innerHTML = `
                <wa-select id="ent-type" label="Tipo de Entidade">
                    ${types.map(t => `<wa-option value="${t}" ${t === initialType ? 'selected' : ''}>${t}</wa-option>`).join('')}
                </wa-select>
                <wa-input id="ent-value" label="Valor" placeholder="ex: example.com"></wa-input>
            `;
        } else {
            body.innerHTML = `
                <label>Tipo de Entidade</label>
                <select id="ent-type">
                    ${types.map(t => `<option value="${t}" ${t === initialType ? 'selected' : ''}>${t}</option>`).join('')}
                </select>
                <label>Valor</label>
                <input type="text" id="ent-value" placeholder="ex: example.com" autofocus>
            `;
        }
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        if (waReady) {
            footer.innerHTML = `
                <wa-button class="cancel" slot="footer" variant="default">Cancelar</wa-button>
                <wa-button class="confirm" slot="footer" variant="primary">Criar e Adicionar</wa-button>
            `;
        } else {
            footer.innerHTML = `
                <button class="btn cancel">Cancelar</button>
                <button class="btn primary confirm">Criar e Adicionar</button>
            `;
        }
        const { close, modal } = this.open({ title: 'Nova Entidade', body, footer });
        const valueInput = modal.querySelector('#ent-value');
        const typeSelect = modal.querySelector('#ent-type');
        // wa-input aceita .focus() quando tem internal input; usa timeout
        // curto para garantir que o upgrade do custom element já rolou
        setTimeout(() => {
            const inner = valueInput.querySelector?.('input') || valueInput;
            inner.focus && inner.focus();
        }, 100);

        modal.querySelector('.cancel').addEventListener('click', close);
        modal.querySelector('.confirm').addEventListener('click', () => {
            const type = typeSelect.value;
            const raw = valueInput.value !== undefined
                ? valueInput.value
                : (valueInput.querySelector?.('input')?.value || '');
            const value = raw.trim();
            if (!value) {
                const inner = valueInput.querySelector?.('input') || valueInput;
                inner.focus && inner.focus();
                return;
            }
            onCreate && onCreate({ type, value });
            close();
        });
    },

    editProperties({ node, onSave }) {
        const waReady = _waReady('wa-dialog') && _waReady('wa-button')
            && _waReady('wa-input');
        const body = document.createElement('div');
        const props = Object.entries(node).filter(([k]) =>
            !['id', 'label', 'type', 'value', 'source', 'target'].includes(k)
        );
        const rowHtml = (k, v) => waReady
            ? `<div class="prop-row" style="padding:0.3rem 0">
                    <wa-input class="prop-k" value="${k}" placeholder="chave" style="width:40%"></wa-input>
                    <wa-input class="prop-v" value="${typeof v === 'object' ? JSON.stringify(v) : v}" placeholder="valor" style="flex:1"></wa-input>
                    <wa-button class="del-prop sm danger" variant="danger" size="small" pill title="Remover"><i class="fa-solid fa-xmark"></i></wa-button>
                </div>`
            : `<div class="prop-row" style="padding:0.3rem 0">
                    <input type="text" class="prop-k" value="${k}" placeholder="chave" style="width:40%">
                    <input type="text" class="prop-v" value="${typeof v === 'object' ? JSON.stringify(v) : v}" placeholder="valor" style="flex:1">
                    <button class="btn sm danger del-prop" title="Remover"><i class="fa-solid fa-xmark"></i></button>
                </div>`;
        body.innerHTML = `
            <p style="margin-top:0; color:var(--text-dim); font-size:0.85rem">
                <strong>${node.label || node.id}</strong>
            </p>
            <div id="props-list">
                ${props.map(([k, v]) => rowHtml(k, v)).join('')}
            </div>
            ${waReady
                ? `<wa-button id="add-prop" size="small" style="margin-top:0.4rem"><i class="fa-solid fa-plus"></i> Adicionar propriedade</wa-button>`
                : `<button class="btn sm" id="add-prop" style="margin-top:0.4rem">
                     <i class="fa-solid fa-plus"></i>Adicionar propriedade
                   </button>`}
        `;
        const footer = document.createElement('div');
        footer.style.display = 'flex';
        footer.style.gap = '0.5rem';
        if (waReady) {
            footer.innerHTML = `
                <wa-button class="cancel" slot="footer" variant="default">Cancelar</wa-button>
                <wa-button class="confirm" slot="footer" variant="primary">Salvar</wa-button>
            `;
        } else {
            footer.innerHTML = `
                <button class="btn cancel">Cancelar</button>
                <button class="btn primary confirm">Salvar</button>
            `;
        }
        const { close, modal } = this.open({ title: 'Editar Propriedades', body, footer });

        const list = modal.querySelector('#props-list');
        modal.querySelector('#add-prop').addEventListener('click', () => {
            const row = document.createElement('div');
            row.className = 'prop-row';
            row.style.padding = '0.3rem 0';
            row.innerHTML = rowHtml('', '');
            list.appendChild(row);
            row.querySelector('.del-prop').addEventListener('click', () => row.remove());
        });

        list.querySelectorAll('.del-prop').forEach(btn => {
            btn.addEventListener('click', (e) => {
                // wa-button é o próprio target; para botão nativo, .closest() acha a row
                const row = e.target.closest ? e.target.closest('.prop-row') : null;
                if (row) row.remove();
            });
        });

        modal.querySelector('.cancel').addEventListener('click', close);
        modal.querySelector('.confirm').addEventListener('click', () => {
            const newProps = {};
            modal.querySelectorAll('.prop-row').forEach(row => {
                const kEl = row.querySelector('.prop-k');
                const vEl = row.querySelector('.prop-v');
                // Para wa-input, ler via .value; fallback para input nativo
                const k = (kEl.value !== undefined ? kEl.value : kEl.querySelector?.('input')?.value || '').trim();
                const v = (vEl.value !== undefined ? vEl.value : vEl.querySelector?.('input')?.value || '').trim();
                if (k) newProps[k] = v;
            });
            onSave && onSave(newProps);
            close();
        });
    },
};

window.Modal = Modal;
