/**
 * Command Palette — UI (issue #133).
 *
 * Camada de apresentação sobre `window.CommandPalette`. Assume que o
 * markup `<dialog id="command-palette">` já foi inserido no DOM
 * (a Lane 3 adiciona em `index.html`).
 *
 * Padrão WAI-ARIA 1.2 combobox: `role="combobox"` no input,
 * `role="listbox"` na `<ul>` e `role="option"` em cada item, com
 * `aria-activedescendant` apontando para o item ativo.
 *
 * Namespace exportado: `window.CommandPaletteUI`.
 *
 * NÃO chamar `init()` automaticamente — `App.init()` (em app.js)
 * é quem coordena o bootstrap dos módulos.
 */
(function () {
    'use strict';

    // ============ Refs do DOM ============

    let dialog = null;
    let input = null;
    let list = null;
    let status = null;
    let empty = null;

    // ============ Estado ============

    let activeIndex = 0;
    let flatResults = [];
    let lastFocus = null;
    let initialized = false;

    const CANONICAL_CATEGORIES = [
        'Navegação',
        'Painel',
        'Grafo',
        'Investigação',
        'Tema',
        'Transforms',
        'Ajuda',
    ];

    // ============ Utilitários ============

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, (c) => (
            { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
        ));
    }

    function isEditable(el) {
        if (!el) return false;
        const t = el.tagName;
        if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT') return true;
        if (el.isContentEditable) return true;
        return false;
    }

    function announce(message, priority) {
        if (window.App && typeof window.App.announce === 'function') {
            window.App.announce(message, priority || 'polite');
        }
    }

    // ============ Render ============

    function render(query) {
        if (!list || !input) return;

        const user = (window.App && window.App.currentUser) || null;
        const fuse = window.CommandPalette.buildIndex(user);

        let results;
        if (query && query.trim() && fuse) {
            const hits = fuse.search(query, { limit: 50 });
            results = hits.map((r) => r.item);
        } else {
            const all = window.CommandPalette.getCommands();
            results = all.slice(0, 50);
        }

        flatResults = results;

        // Mantém activeIndex dentro dos limites após nova busca.
        if (activeIndex >= flatResults.length) {
            activeIndex = Math.max(0, flatResults.length - 1);
        }

        if (flatResults.length === 0) {
            list.innerHTML = '';
            if (empty) {
                empty.hidden = false;
                empty.textContent = query
                    ? 'Nenhum comando encontrado para “' + query + '”'
                    : 'Nenhum comando disponível';
            }
            input.setAttribute('aria-activedescendant', '');
            if (status) status.textContent = '0 resultados disponíveis';
            return;
        }

        if (empty) empty.hidden = true;

        // Agrupa por categoria na ordem canônica.
        const buckets = new Map();
        CANONICAL_CATEGORIES.forEach((c) => buckets.set(c, []));
        for (const cmd of flatResults) {
            const cat = buckets.has(cmd.category) ? cmd.category : 'Ajuda';
            buckets.get(cat).push(cmd);
        }

        const html = [];
        let runningIdx = 0;
        for (const [category, cmds] of buckets) {
            if (!cmds || cmds.length === 0) continue;
            html.push('<li class="cp-group" role="presentation">' + escapeHtml(category) + '</li>');
            for (const cmd of cmds) {
                const idx = runningIdx;
                const isActive = idx === activeIndex;
                const icon = escapeHtml(cmd.icon || 'square');
                const label = escapeHtml(cmd.label);
                const hint = escapeHtml(cmd.hint || '');
                const shortcut = escapeHtml(cmd.shortcut || '');
                const id = escapeHtml(cmd.id);
                html.push(
                    '<li id="cp-opt-' + idx + '" role="option" class="cp-item' + (isActive ? ' active' : '') + '"' +
                    ' aria-selected="' + (isActive ? 'true' : 'false') + '"' +
                    ' data-id="' + id + '"' +
                    ' data-idx="' + idx + '">' +
                    '<i data-lucide="' + icon + '" aria-hidden="true"></i>' +
                    '<span class="cp-label">' + label + '</span>' +
                    (hint ? '<span class="cp-hint">' + hint + '</span>' : '') +
                    (shortcut ? '<kbd class="cp-shortcut">' + shortcut + '</kbd>' : '') +
                    '</li>'
                );
                runningIdx += 1;
            }
        }

        list.innerHTML = html.join('');

        // Re-renderiza os SVGs do Lucide.
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            try {
                window.lucide.createIcons();
            } catch (e) {
                // Falha silenciosa: ícones caem para texto vazio (decorativo).
            }
        }

        // Atualiza aria-activedescendant no input.
        if (flatResults[activeIndex]) {
            input.setAttribute('aria-activedescendant', 'cp-opt-' + activeIndex);
        } else {
            input.setAttribute('aria-activedescendant', '');
        }

        if (status) {
            status.textContent = flatResults.length + ' resultado' + (flatResults.length === 1 ? '' : 's') + ' disponível' + (flatResults.length === 1 ? '' : 'is');
        }
    }

    function setActive(delta) {
        if (!list || flatResults.length === 0) return;
        const len = flatResults.length;
        let next;
        if (delta === -Infinity) next = 0;
        else if (delta === Infinity) next = len - 1;
        else next = (activeIndex + delta + len) % len;

        if (next === activeIndex) return;
        activeIndex = next;
        updateActiveDom();
    }

    function updateActiveDom() {
        if (!list || !input) return;
        const items = list.querySelectorAll('[role="option"]');
        items.forEach((el) => {
            const idx = Number(el.getAttribute('data-idx'));
            const isActive = idx === activeIndex;
            el.classList.toggle('active', isActive);
            el.setAttribute('aria-selected', isActive ? 'true' : 'false');
        });
        if (flatResults[activeIndex]) {
            input.setAttribute('aria-activedescendant', 'cp-opt-' + activeIndex);
            const activeEl = list.querySelector('#cp-opt-' + activeIndex);
            if (activeEl && typeof activeEl.scrollIntoView === 'function') {
                activeEl.scrollIntoView({ block: 'nearest' });
            }
        } else {
            input.setAttribute('aria-activedescendant', '');
        }
    }

    // ============ Open / Close / Toggle ============

    function open() {
        if (!dialog) return;
        lastFocus = document.activeElement;
        try {
            if (typeof dialog.showModal === 'function') {
                dialog.showModal();
            } else {
                dialog.setAttribute('open', '');
            }
        } catch (e) {
            // Se já estiver aberto, ignora.
        }
        if (input) {
            input.value = '';
            activeIndex = 0;
            // requestAnimationFrame dá tempo do dialog pintar antes de focar.
            requestAnimationFrame(() => {
                if (input) input.focus();
            });
        }
        render('');
        announce('Paleta de comandos aberta', 'polite');
    }

    function close() {
        if (!dialog) return;
        if (typeof dialog.close === 'function') {
            try { dialog.close(); } catch (e) { dialog.removeAttribute('open'); }
        } else {
            dialog.removeAttribute('open');
        }
        if (input) input.value = '';
        flatResults = [];
        activeIndex = 0;
        if (lastFocus && typeof lastFocus.focus === 'function') {
            try { lastFocus.focus(); } catch (e) { /* ignore */ }
        }
        announce('Paleta de comandos fechada', 'polite');
    }

    function toggle() {
        if (!dialog) return;
        if (dialog.open) close();
        else open();
    }

    // ============ Event listeners ============

    function bindEvents() {
        if (!input || !list || !dialog) return;

        input.addEventListener('input', (e) => {
            activeIndex = 0;
            render(e.target.value);
        });

        input.addEventListener('keydown', (e) => {
            switch (e.key) {
                case 'ArrowDown':
                    e.preventDefault();
                    setActive(1);
                    break;
                case 'ArrowUp':
                    e.preventDefault();
                    setActive(-1);
                    break;
                case 'Home':
                    e.preventDefault();
                    setActive(-Infinity);
                    break;
                case 'End':
                    e.preventDefault();
                    setActive(Infinity);
                    break;
                case 'Enter': {
                    e.preventDefault();
                    const opt = list.querySelector('#cp-opt-' + activeIndex);
                    if (opt) {
                        const id = opt.getAttribute('data-id');
                        const cp = window.CommandPalette;
                        close();
                        if (cp && id) cp.run(id);
                    }
                    break;
                }
                case 'Escape':
                    e.preventDefault();
                    close();
                    break;
                case 'Tab':
                    // Mantém foco dentro da paleta (combobox pattern).
                    e.preventDefault();
                    break;
                default:
                    break;
            }
        });

        list.addEventListener('click', (e) => {
            const li = e.target.closest('[role="option"]');
            if (!li) return;
            const id = li.getAttribute('data-id');
            const cp = window.CommandPalette;
            close();
            if (cp && id) cp.run(id);
        });

        list.addEventListener('mousemove', (e) => {
            const li = e.target.closest('[role="option"]');
            if (!li) return;
            const idx = Number(li.getAttribute('data-idx'));
            if (!Number.isNaN(idx) && idx !== activeIndex) {
                activeIndex = idx;
                updateActiveDom();
            }
        });

        // Click no backdrop fecha (event.target === dialog).
        dialog.addEventListener('click', (e) => {
            if (e.target === dialog) close();
        });

        dialog.addEventListener('close', () => {
            if (input) input.value = '';
            flatResults = [];
            activeIndex = 0;
        });

        // Atalho global: ⌘K / Ctrl+K alterna; "?" abre quando nenhum
        // input/textarea/contenteditable tem foco. Esses atalhos não
        // conflitam com o handler global em app.js (Cmd+K e ? estão livres).
        document.addEventListener('keydown', (e) => {
            // Cmd+K / Ctrl+K
            if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey &&
                (e.key === 'k' || e.key === 'K')) {
                e.preventDefault();
                toggle();
                return;
            }
            // "?" — Shift+"/" em teclado US. Ignora em inputs.
            if (!e.metaKey && !e.ctrlKey && !e.altKey &&
                (e.key === '?' || (e.shiftKey && e.key === '/'))) {
                if (isEditable(e.target)) return;
                e.preventDefault();
                if (!dialog.open) open();
            }
        });
    }

    // ============ Init ============

    function init() {
        if (initialized) return;
        dialog = document.getElementById('command-palette');
        input = document.getElementById('cp-input');
        list = document.getElementById('cp-results');
        status = document.getElementById('cp-status');
        empty = document.getElementById('cp-empty');

        if (!dialog || !input || !list) {
            console.warn('[CommandPaletteUI] markup ausente (#command-palette, #cp-input, #cp-results)');
            return;
        }

        bindEvents();
        initialized = true;
    }

    // ============ Export ============

    window.CommandPaletteUI = {
        init,
        open,
        close,
        toggle,
        render,
    };
})();
