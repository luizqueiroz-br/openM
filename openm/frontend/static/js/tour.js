/**
 * Onboarding Tour — issue #134.
 *
 * Tour de boas-vindas guiado em 5 passos que destaca os principais elementos
 * da UI logo após o primeiro login. Implementação 100% vanilla (sem
 * Driver.js / Shepherd.js) usando `<wa-dialog>` do Web Awesome 3.10.x para
 * os popovers e CSS `box-shadow: 0 0 0 9999px` para o spotlight cutout.
 *
 * API pública (window.OpenMTour):
 *   - start({ force = false }) — inicia o tour. `force` ignora persistência.
 *   - reset() — limpa persistência e reinicia.
 *   - getCurrentStep() — índice do passo atual (0..4) ou null se inativo.
 *   - isActive() — true se o tour está em execução.
 *
 * Persistência (localStorage):
 *   - openm.tour.onboarding.completed   'true' | 'false'
 *   - openm.tour.onboarding.dismissedAt ISO 8601
 *   - openm.tour.onboarding.version     '1'
 *   - openm.tour.onboarding.currentStep '0'..'4'
 *
 * Mobile (≤768px): o auto-start é suprimido — tour só roda via chamada
 * manual (Command Palette `help.replay-tour`). No mobile, o `<wa-dialog>`
 * recebe a classe `tour-mobile` que o força a fullscreen (Lane 3 Layout).
 *
 * Acessibilidade (WCAG 2.2 AA — issue #128):
 *   - aria-live="polite" anuncia "Passo N de M: <título>" em cada troca.
 *   - Botões Voltar/Pular/Próximo com aria-labels em PT-BR.
 *   - ESC + light-dismiss disparam `_skip()` (não completa o tour).
 *   - Enter (fora de textareas) avança; ArrowLeft volta; ArrowRight avança.
 *   - `prefers-reduced-motion` desativa todas as animações (CSS).
 *   - `prefers-contrast: more` engrossa borda do spotlight e cards.
 *
 * Pré-requisitos:
 *   - `window.App` (app.js) com `_isMobile()`, `_isTablet()`, `announce()`,
 *     `closeAllDrawers()`.
 *   - `<wa-dialog>` registrado pelo `webawesome.loader.js` (Lane 4B corrige
 *     a URL CDN de `@awesome.me/awesome@3` para `@awesome.me/webawesome@3`).
 *   - Lucide (`window.lucide.createIcons()`) para renderizar os ícones dos
 *     passos e do botão close.
 */
(function () {
    'use strict';

    // ──────────── Constantes ────────────

    const TOUR_VERSION = 1;
    const STORAGE_PREFIX = 'openm.tour.onboarding';

    /**
     * Os 5 passos do tour. Cada um mapeia um elemento da UI real.
     * `popoverPosition` é a preferência inicial caso o auto-fit caiba;
     * se não couber, `positionPopover()` escolhe o melhor lado.
     * `icon` é o nome Lucide exibido no header do popover.
     */
    const STEPS = [
        {
            id: 'welcome',
            title: 'Boas-vindas ao OpenM',
            desc: 'OpenM é seu workspace de OSINT modular. Crie investigações, conecte entidades e rode transforms para descobrir relações.',
            selector: 'body',
            popoverPosition: 'center',
            icon: 'git-fork',
            showLogo: true,
        },
        {
            id: 'palette',
            title: 'Sua paleta de entidades',
            desc: 'Arraste cards da paleta para o canvas. Cada tipo (domínio, pessoa, CNPJ, ação) tem cor e formato próprios.',
            selector: '#palette-items',
            popoverPosition: 'right',
            icon: 'mouse-pointer-click',
        },
        {
            id: 'canvas',
            title: 'O canvas do grafo',
            desc: 'Pan com arrastar, zoom com scroll, duplo-clique em um nó abre o Inspector. Conecte entidades arrastando de uma a outra.',
            selector: '#cy',
            popoverPosition: 'bottom',
            icon: 'move',
        },
        {
            id: 'inspector',
            title: 'Inspector de detalhes',
            desc: 'Quando um nó está selecionado, o Inspector mostra propriedades, sightings e transforms aplicáveis no painel direito.',
            selector: '#inspector-content',
            popoverPosition: 'left',
            icon: 'panel-right',
        },
        {
            id: 'topbar',
            title: 'Salvar, buscar e tema',
            desc: '⌘S salva, ⌘F abre a busca global, ⌘⇧T alterna tema. Tudo também está no Command Palette (⌘K).',
            selector: '.topbar',
            popoverPosition: 'bottom-right',
            icon: 'keyboard',
            chips: ['⌘S', '⌘F', '⌘⇧T'],
        },
    ];

    // ──────────── Helpers privados ────────────

    /**
     * Espelha `modals.js:13-15` — `true` se o custom element `<wa-dialog>`
     * (ou qualquer tag) já foi registrado pelo `webawesome.loader.js`.
     * O `webawesome` carrega via dynamic import e registra sob demanda,
     * então o tour precisa esperar (até 3s com polling 50ms).
     */
    function _waReady(tag) {
        return typeof window !== 'undefined'
            && !!window.customElements
            && customElements.get(tag) !== undefined;
    }

    /**
     * Espera `tag` registrar (max 3s, polling 50ms). Resolve true quando
     * o componente estiver pronto ou false se o timeout estourar.
     */
    function _waitWaReady(tag) {
        return new Promise((resolve) => {
            if (_waReady(tag)) { resolve(true); return; }
            const start = Date.now();
            const id = setInterval(() => {
                if (_waReady(tag)) {
                    clearInterval(id);
                    resolve(true);
                } else if (Date.now() - start > 3000) {
                    clearInterval(id);
                    resolve(false);
                }
            }, 50);
        });
    }

    // ──────────── Estado do módulo ────────────

    let currentStep = 0;
    let isActive = false;
    let tourDialog = null;
    let spotlight = null;
    let shield = null;
    let announcer = null;
    let resizeRafId = null;
    let boundEscListener = null;
    let positionRAF = null;

    // ──────────── Construção dinâmica de markup ────────────

    /**
     * Cria o `<wa-dialog>`, spotlight, click-shield e announcer no DOM.
     * É idempotente — se já existem (de um start anterior), reaproveita.
     * Tudo é auto-contido em #tour-root, sem dependência de markup pré-existente
     * no `index.html`.
     */
    function _ensureMarkup() {
        if (tourDialog) return;

        // Container raiz (se não existir) — fica como filho de <body>.
        let root = document.getElementById('tour-root');
        if (!root) {
            root = document.createElement('div');
            root.id = 'tour-root';
            document.body.appendChild(root);
        }

        // 1) Click-shield transparente — captura ESC/clicks acidentais
        //    para o dialog (que tem light-dismiss) interpretar como dismiss.
        //    O shield em si é não-interativo (pointer-events: none) — ele
        //    só garante que nenhum outro elemento da UI fique clicável
        //    acima do z-index do dialog, o que poderia quebrar o dismiss.
        shield = document.createElement('div');
        shield.className = 'tour-click-shield';
        shield.hidden = true;
        shield.setAttribute('aria-hidden', 'true');
        root.appendChild(shield);

        // 2) Spotlight — retângulo highlight do alvo. A `box-shadow` gigante
        //    cria o "buraco" no backdrop escuro. Ver tour.css.
        spotlight = document.createElement('div');
        spotlight.className = 'tour-spotlight';
        spotlight.hidden = true;
        spotlight.setAttribute('aria-hidden', 'true');
        root.appendChild(spotlight);

        // 3) Dialog principal (popover). Sem header WA (without-header) —
        //    renderizamos header interno com contador + close button.
        tourDialog = document.createElement('wa-dialog');
        tourDialog.id = 'tour-popover';
        tourDialog.setAttribute('label', 'Tour');
        tourDialog.setAttribute('without-header', '');
        tourDialog.setAttribute('light-dismiss', '');
        tourDialog.style.setProperty('--width', '380px');
        tourDialog.classList.add('tour-popover');
        // Conteúdo do popover — counter, header, body, footer.
        // Slots do WA: default (body), footer (botões), label (counter em
        // aria-live polite).
        tourDialog.innerHTML = `
            <div class="tour-header" slot="header">
                <div class="tour-counter" aria-live="polite" aria-atomic="true">Tour 1/${STEPS.length}</div>
                <button class="tour-close" type="button" aria-label="Fechar tour">
                    <i data-lucide="x" aria-hidden="true"></i>
                </button>
            </div>
            <div class="tour-body">
                <div class="tour-icon-wrap" aria-hidden="true">
                    <i class="tour-icon" data-lucide="git-fork"></i>
                </div>
                <h3 class="tour-title">Tour</h3>
                <p class="tour-desc">Descrição do passo.</p>
                <div class="tour-chips" hidden></div>
            </div>
            <div class="tour-footer" slot="footer">
                <button id="tour-prev" class="wa-button wa-button--outlined" type="button" aria-label="Passo anterior">Voltar</button>
                <button id="tour-skip" class="wa-button wa-button--text" type="button" aria-label="Pular e fechar o tour">Pular</button>
                <button id="tour-next" class="wa-button wa-button--brand" type="button" aria-label="Próximo passo">Próximo →</button>
            </div>
        `;
        root.appendChild(tourDialog);

        // 4) Announcer — região aria-live dedicada para "Passo N de M".
        //    Separada do #sr-status do App porque queremos prioridade
        //    dedicada e evitar flood do toast.
        announcer = document.createElement('div');
        announcer.className = 'tour-announcer';
        announcer.setAttribute('aria-live', 'polite');
        announcer.setAttribute('aria-atomic', 'true');
        root.appendChild(announcer);

        // ── Listeners internos ──
        // Cliques: usa event delegation no dialog (mais robusto que
        // addEventListener em cada botão, sobrevive a re-render do WA).
        tourDialog.addEventListener('click', (ev) => {
            const t = ev.target;
            if (!(t instanceof Element)) return;
            if (t.closest('#tour-next')) _next();
            else if (t.closest('#tour-prev')) _prev();
            else if (t.closest('#tour-skip')) _skip();
            else if (t.closest('.tour-close')) _skip();
        });

        // Atalho de teclado quando o foco está dentro do dialog.
        tourDialog.addEventListener('keydown', _onDialogKeydown);

        // WA events: light-dismiss + ESC disparam `wa-hide`. Tratamos
        // como `_skip()` (não `_complete()`) — o usuário não navegou
        // até o fim.
        tourDialog.addEventListener('wa-hide', () => {
            if (isActive) _skip();
        });

        // Reposiciona em resize (debounced via rAF) para o popover
        // acompanhar o alvo quando o usuário gira o tablet ou redimensiona.
        window.addEventListener('resize', () => {
            if (!isActive) return;
            if (resizeRafId) cancelAnimationFrame(resizeRafId);
            resizeRafId = requestAnimationFrame(() => {
                if (isActive) _showStep(currentStep);
            });
        });
    }

    /**
     * Aplica `tour-mobile` no dialog se a viewport for tablet (≤1024px).
     * No mobile, o CSS força fullscreen (inset:0, sem border-radius).
     */
    function _ensureMobileClass() {
        if (!tourDialog || !window.App) return;
        const tablet = typeof window.App._isTablet === 'function' && window.App._isTablet();
        tourDialog.classList.toggle('tour-mobile', !!tablet);
    }

    // ──────────── Posicionamento do popover ────────────

    /**
     * Auto-fit: escolhe o lado (bottom/top/right/left) que maximiza a
     * área visível do popover dentro do viewport. Bônus 1.2× para `bottom`
     * quando cabe — convenção de UX (popovers caem do alvo, não sobem).
     *
     * @param {HTMLElement} dialog
     * @param {Element} target
     * @param {string} preference — 'right' | 'left' | 'bottom' | 'bottom-right' | 'center'
     */
    function positionPopover(dialog, target, preference) {
        if (!dialog || !target) return;

        // Passo "body" (welcome) sempre centraliza independente da preference.
        if (preference === 'center' || !target || target === document.body) {
            const dw = dialog.offsetWidth || 380;
            const dh = dialog.offsetHeight || 200;
            const vw = window.innerWidth;
            const vh = window.innerHeight;
            const x = Math.max(8, (vw - dw) / 2);
            const y = Math.max(8, (vh - dh) / 2);
            dialog.style.transform = `translate(${x}px, ${y}px)`;
            return;
        }

        const rect = target.getBoundingClientRect();
        const dw = dialog.offsetWidth || 380;
        const dh = dialog.offsetHeight || 200;
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const gap = 12; // distância entre popover e alvo
        const pad = 8;  // margem mínima das bordas do viewport

        // Candidatos: cada um com x, y e "visible ratio" (área visível /
        // área total). O melhor é o de maior ratio, com bônus para a
        // preferência quando o ratio está próximo de 1.
        const candidates = [];

        // bottom — popover abaixo do alvo
        candidates.push({
            pos: 'bottom',
            x: rect.left + rect.width / 2 - dw / 2,
            y: rect.bottom + gap,
        });
        // top — popover acima do alvo
        candidates.push({
            pos: 'top',
            x: rect.left + rect.width / 2 - dw / 2,
            y: rect.top - dh - gap,
        });
        // right — popover à direita do alvo
        candidates.push({
            pos: 'right',
            x: rect.right + gap,
            y: rect.top + rect.height / 2 - dh / 2,
        });
        // left — popover à esquerda do alvo
        candidates.push({
            pos: 'left',
            x: rect.left - dw - gap,
            y: rect.top + rect.height / 2 - dh / 2,
        });

        // bottom-right — alinhado à direita, abaixo (usado pelo passo topbar)
        candidates.push({
            pos: 'bottom-right',
            x: rect.right - dw,
            y: rect.bottom + gap,
        });

        // Score cada candidato.
        let best = null;
        let bestScore = -Infinity;
        for (const c of candidates) {
            // Clamp dentro do viewport.
            const xClamped = Math.max(pad, Math.min(c.x, vw - dw - pad));
            const yClamped = Math.max(pad, Math.min(c.y, vh - dh - pad));

            // Área visível (interseção com viewport).
            const x1 = Math.max(xClamped, 0);
            const y1 = Math.max(yClamped, 0);
            const x2 = Math.min(xClamped + dw, vw);
            const y2 = Math.min(yClamped + dh, vh);
            const visibleW = Math.max(0, x2 - x1);
            const visibleH = Math.max(0, y2 - y1);
            const visibleArea = visibleW * visibleH;
            const totalArea = dw * dh;
            const ratio = totalArea > 0 ? visibleArea / totalArea : 0;

            let score = ratio;
            // Bônus para a preferência declarada (só se a posição couber
            // com ratio > 0.7 — não premiamos posições cortadas).
            if (c.pos === preference && ratio > 0.7) {
                score *= 1.2;
            }
            // Bônus leve para "bottom" como fallback (UX convention).
            if (c.pos === 'bottom' && ratio > 0.8 && preference !== 'top' && preference !== 'left') {
                score *= 1.05;
            }

            if (score > bestScore) {
                bestScore = score;
                best = { ...c, x: xClamped, y: yClamped, score };
            }
        }

        if (best) {
            dialog.style.transform = `translate(${best.x}px, ${best.y}px)`;
        }
    }

    // ──────────── Render do passo atual ────────────

    /**
     * Mostra o passo `index`. Idempotente em `currentStep` — pode ser
     * chamado várias vezes (resize, retry de esc) sem efeito colateral.
     */
    function _showStep(index) {
        if (!tourDialog) return;
        const step = STEPS[index];
        if (!step) {
            _complete();
            return;
        }

        // ── Atualiza textos ──
        const counter = tourDialog.querySelector('.tour-counter');
        const titleEl = tourDialog.querySelector('.tour-title');
        const descEl = tourDialog.querySelector('.tour-desc');
        const iconEl = tourDialog.querySelector('.tour-icon');
        const iconWrap = tourDialog.querySelector('.tour-icon-wrap');
        const chipsEl = tourDialog.querySelector('.tour-chips');
        const prevBtn = tourDialog.querySelector('#tour-prev');
        const nextBtn = tourDialog.querySelector('#tour-next');

        if (counter) counter.textContent = `Tour ${index + 1}/${STEPS.length}`;
        if (titleEl) titleEl.textContent = step.title;
        if (descEl) descEl.textContent = step.desc;

        if (iconEl) {
            iconEl.setAttribute('data-lucide', step.icon || 'circle');
        }
        if (iconWrap) {
            // No passo 1 (welcome) o ícone vai num quadrado 72×72 com pulse
            // (CSS .tour-icon-wrap--logo). Nos outros, é só um chip 32×32.
            iconWrap.classList.toggle('tour-icon-wrap--logo', !!step.showLogo);
        }

        // Chips de atalhos (passo 5 — topbar).
        if (chipsEl) {
            if (step.chips && step.chips.length) {
                chipsEl.hidden = false;
                chipsEl.innerHTML = step.chips
                    .map((c) => `<span class="tour-chip" aria-hidden="true">${c}</span>`)
                    .join('');
            } else {
                chipsEl.hidden = true;
                chipsEl.innerHTML = '';
            }
        }

        // Estado dos botões.
        if (prevBtn) prevBtn.disabled = index === 0;
        if (nextBtn) {
            const last = index === STEPS.length - 1;
            nextBtn.textContent = last ? 'Concluir' : 'Próximo →';
            nextBtn.setAttribute('aria-label', last ? 'Concluir tour' : 'Próximo passo');
        }

        // ── Spotlight & target ──
        if (step.selector === 'body' || !step.selector) {
            // Passo de boas-vindas: sem spotlight, dialog centralizado.
            if (spotlight) spotlight.hidden = true;
            positionPopover(tourDialog, document.body, 'center');
        } else {
            const target = document.querySelector(step.selector);
            if (!target) {
                // Alvo sumiu do DOM (ex: usuário fechou a sidebar) —
                // avança silenciosamente.
                console.warn(`[OpenMTour] target "${step.selector}" not found, skipping step`);
                if (index < STEPS.length - 1) {
                    currentStep = index + 1;
                    if (positionRAF) cancelAnimationFrame(positionRAF);
                    positionRAF = requestAnimationFrame(() => _showStep(currentStep));
                } else {
                    _complete();
                }
                return;
            }

            if (spotlight) {
                const r = target.getBoundingClientRect();
                spotlight.style.left = `${r.left - 4}px`;
                spotlight.style.top = `${r.top - 4}px`;
                spotlight.style.width = `${r.width + 8}px`;
                spotlight.style.height = `${r.height + 8}px`;
                spotlight.hidden = false;
            }

            // Garante que o alvo está visível antes de posicionar.
            try {
                target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            } catch (e) {
                // Silent — alguns browsers antigos podem não suportar smooth.
            }

            // Posiciona no próximo frame para o scroll já ter atualizado
            // o getBoundingClientRect.
            if (positionRAF) cancelAnimationFrame(positionRAF);
            positionRAF = requestAnimationFrame(() => {
                if (spotlight && !spotlight.hidden && target) {
                    const r = target.getBoundingClientRect();
                    spotlight.style.left = `${r.left - 4}px`;
                    spotlight.style.top = `${r.top - 4}px`;
                    spotlight.style.width = `${r.width + 8}px`;
                    spotlight.style.height = `${r.height + 8}px`;
                }
                positionPopover(tourDialog, target, step.popoverPosition || 'bottom');
            });
        }

        // ── Mobile class (pode ter mudado via resize) ──
        _ensureMobileClass();

        // ── Re-renderiza Lucide (ícone do header + ícone principal) ──
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            try { window.lucide.createIcons(); } catch (e) { /* silent */ }
        }

        // ── A11y announce ──
        if (announcer) {
            announcer.textContent = `Passo ${index + 1} de ${STEPS.length}: ${step.title}`;
        }

        // ── Persistência: salva o passo atual (recuperação em reload) ──
        try {
            localStorage.setItem(`${STORAGE_PREFIX}.currentStep`, String(index));
        } catch (e) { /* localStorage indisponível — silent */ }
    }

    // ──────────── Navegação entre passos ────────────

    function _next() {
        if (currentStep < STEPS.length - 1) {
            currentStep += 1;
            _showStep(currentStep);
        } else {
            _complete();
        }
    }

    function _prev() {
        if (currentStep > 0) {
            currentStep -= 1;
            _showStep(currentStep);
        }
    }

    function _skip() {
        _end(false);
    }

    function _complete() {
        _end(true);
    }

    /**
     * Encerra o tour. `completed=true` marca como concluído (não mostra de
     * novo no auto-start). `completed=false` só marca dismissedAt — tour
     * pode ser invocado manualmente via Command Palette.
     */
    function _end(completed) {
        if (!isActive && !tourDialog) return;
        isActive = false;

        if (tourDialog) {
            try { tourDialog.open = false; } catch (e) { /* silent */ }
        }
        if (spotlight) spotlight.hidden = true;
        if (shield) shield.hidden = true;
        currentStep = 0;

        try {
            localStorage.setItem(`${STORAGE_PREFIX}.dismissedAt`, new Date().toISOString());
            localStorage.setItem(`${STORAGE_PREFIX}.version`, String(TOUR_VERSION));
            localStorage.setItem(`${STORAGE_PREFIX}.currentStep`, '0');
            if (completed) {
                localStorage.setItem(`${STORAGE_PREFIX}.completed`, 'true');
            }
        } catch (e) { /* silent */ }

        if (window.App && typeof window.App.announce === 'function') {
            window.App.announce(
                completed ? 'Tour concluído' : 'Tour fechado',
                'polite',
            );
        }
    }

    // ──────────── Atalho de teclado dentro do dialog ────────────

    function _onDialogKeydown(ev) {
        // Não intercepta quando o usuário está digitando (campo de busca
        // no topo, etc.) — só queremos os atalhos de navegação.
        if (window.App && typeof window.App._isEditable === 'function'
            && window.App._isEditable(ev.target)) {
            // Exceção: textarea é editável mas Enter dentro dele é quebra
            // de linha, não avanço. Input também — Enter submete form.
            if (ev.key === 'Enter') return;
        }

        if (ev.key === 'Enter') {
            ev.preventDefault();
            _next();
        } else if (ev.key === 'ArrowLeft') {
            ev.preventDefault();
            _prev();
        } else if (ev.key === 'ArrowRight') {
            ev.preventDefault();
            _next();
        }
    }

    // ──────────── API pública ────────────

    /**
     * Inicia o tour. Se `force=true`, ignora flags de persistência e
     * mostra mesmo que o usuário já tenha completado antes.
     *
     * Auto-start suprimido em mobile (≤768px) — drawer mobile complica
     * o spotlight. Usuário pode disparar manualmente via Command Palette.
     */
    async function start({ force = false } = {}) {
        // Espera o componente WA registrar (loader é async).
        const ready = await _waitWaReady('wa-dialog');
        if (!ready) {
            console.warn('[OpenMTour] <wa-dialog> não carregou em 3s — abortando tour');
            return;
        }

        if (!force) {
            try {
                if (localStorage.getItem(`${STORAGE_PREFIX}.completed`) === 'true') return;
                if (localStorage.getItem(`${STORAGE_PREFIX}.dismissedAt`)) return;
            } catch (e) { /* silent */ }
        }

        // Auto-start em mobile suprimido (UX: spotlight + drawer = ruim).
        if (!force && window.App && typeof window.App._isMobile === 'function'
            && window.App._isMobile()) {
            return;
        }

        // Fecha drawers mobile antes de mostrar o tour (importante —
        // drawer aberto cortaria o spotlight).
        if (window.App && typeof window.App.closeAllDrawers === 'function') {
            try { window.App.closeAllDrawers(); } catch (e) { /* silent */ }
        }

        _ensureMarkup();
        _ensureMobileClass();

        currentStep = 0;
        isActive = true;

        if (shield) shield.hidden = false;
        try {
            tourDialog.open = true;
        } catch (e) {
            // Fallback para versões WA que ainda usam .show()
            if (typeof tourDialog.show === 'function') tourDialog.show();
        }

        // Espera 1 frame para o dialog terminar de animar entrada e o
        // browser computar offsetWidth/Height antes do positionPopover.
        requestAnimationFrame(() => _showStep(0));
    }

    /** Limpa persistência e reinicia. Usado pelo command help.replay-tour. */
    function reset() {
        try {
            localStorage.removeItem(`${STORAGE_PREFIX}.completed`);
            localStorage.removeItem(`${STORAGE_PREFIX}.dismissedAt`);
            localStorage.removeItem(`${STORAGE_PREFIX}.version`);
            localStorage.removeItem(`${STORAGE_PREFIX}.currentStep`);
        } catch (e) { /* silent */ }
        return start({ force: true });
    }

    function getCurrentStep() {
        return isActive ? currentStep : null;
    }

    function isActiveFn() {
        return isActive;
    }

    // ──────────── Exposição ────────────

    window.OpenMTour = {
        start,
        reset,
        getCurrentStep,
        isActive: isActiveFn,
    };
})();
