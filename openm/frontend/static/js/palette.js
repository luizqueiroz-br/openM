/**
 * Palette - painel esquerdo com entidades arrastáveis e drag-and-drop para o canvas.
 *
 * Nota (issue #127, parte 2): o markup `.palette-item` é mantido como está.
 * A migração para `<wa-tree-item>` está planejada para fase posterior
 * (WA tree API está marcada como imatura no discovery).
 */

const Palette = {
    el: null,
    searchEl: null,
    dragGhost: null,
    currentDragType: null,

    init() {
        this.el = document.getElementById('palette-items');
        this.searchEl = document.getElementById('search-input');
        this.render();
        this.searchEl.addEventListener('input', () => this.render());
        this.setupDragDrop();
    },

    render() {
        const filter = this.searchEl.value.toLowerCase().trim();
        const types = Object.keys(ENTITY_ICONS).filter(t => t !== 'Generic');
        const filtered = types.filter(t => t.toLowerCase().includes(filter));

        this.el.innerHTML = filtered.map(type => {
            const meta = ENTITY_ICONS[type];
            return `
                <div class="palette-item" draggable="true" data-type="${type}">
                    <div class="icon" style="background:${meta.color}">
                        <i class="fa-solid ${meta.icon}"></i>
                    </div>
                    <div class="label">
                        ${type}
                        <small>${this._getDescription(type)}</small>
                    </div>
                </div>
            `;
        }).join('');

        // Eventos de drag
        this.el.querySelectorAll('.palette-item').forEach(item => {
            item.addEventListener('dragstart', (e) => this.onDragStart(e, item.dataset.type));
            item.addEventListener('dragend', () => this.onDragEnd());
        });
    },

    _getDescription(type) {
        const map = {
            Domain: 'Domínio / hostname',
            IPAddress: 'Endereço IP',
            Email: 'Endereço de e-mail',
            Person: 'Pessoa física',
            BankAccount: 'Conta bancária',
            Device: 'Dispositivo',
        };
        return map[type] || '';
    },

    onDragStart(e, type) {
        this.currentDragType = type;
        e.dataTransfer.setData('text/plain', `palette:${type}`);
        e.dataTransfer.effectAllowed = 'copy';

        // Ghost customizado
        this.createDragGhost(type, e);
    },

    createDragGhost(type, e) {
        const meta = ENTITY_ICONS[type];
        this.dragGhost = document.createElement('div');
        this.dragGhost.className = 'drag-ghost';
        this.dragGhost.innerHTML = `
            <div class="palette-item">
                <div class="icon" style="background:${meta.color}">
                    <i class="fa-solid ${meta.icon}"></i>
                </div>
                <div class="label">${type}</div>
            </div>
        `;
        this.dragGhost.style.left = `${e.clientX}px`;
        this.dragGhost.style.top = `${e.clientY}px`;
        document.getElementById('drag-ghost-root').appendChild(this.dragGhost);
    },

    onDragEnd() {
        if (this.dragGhost) {
            this.dragGhost.remove();
            this.dragGhost = null;
        }
        this.currentDragType = null;
    },

    setupDragDrop() {
        // Habilita o canvas a receber drops da paleta
        const canvas = document.querySelector('.canvas-area');
        canvas.addEventListener('dragover', (e) => {
            if (e.dataTransfer.types.includes('text/plain')) {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'copy';
            }
        });
        canvas.addEventListener('drop', async (e) => {
            const data = e.dataTransfer.getData('text/plain');
            if (!data.startsWith('palette:')) return;
            e.preventDefault();

            const type = data.split(':')[1];
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            Modal.createEntity({
                initialType: type,
                onCreate: ({ type, value }) => {
                    window.App.createEntity(type, value, { x, y });
                },
            });
        });
    },
};

window.Palette = Palette;
