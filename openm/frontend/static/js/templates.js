/**
 * Templates Registry — issue #134.
 *
 * 5 templates (4 especializados + 1 blank) que povoam a galeria de
 * "Nova Investigation". Cada template define:
 *   - ícone Lucide + cor de fundo
 *   - root node (entidade inicial — null no blank)
 *   - transforms pré-selecionados (rodam no `apply-template` se backend
 *     suportar, ver TODO Lane 4B)
 *   - tier (free, registered) para gating de visibilidade por RBAC
 *
 * A visibilidade por role é resolvida em `getVisible(user)` via
 * `OpenMPermissions.can(role, action)`. O `tier` é convertido em
 * `investigation:create` por padrão — só admin/analyst criam investigação,
 * que é o gate já existente no backend.
 *
 * API pública (window.OpenMTemplates):
 *   - TEMPLATES: array imutável de templates
 *   - getVisible(user): filtra por role do user
 *   - openGallery(): abre o <wa-dialog> com grid de cards
 */
(function () {
    'use strict';

    // ──────────── Catálogo de templates ────────────

    /**
     * Shape:
     *   id          — slug único, kebab-case
     *   label       — texto do card (PT-BR)
     *   desc        — descrição 1 linha, max ~80 chars
     *   icon        — nome Lucide
     *   bg          — var CSS do token de cor
     *   rootNode    — { type, value } | null
     *   transforms  — array de nomes de transform (referência ao registry
     *                 do Transform Hub, ver transforms.js)
     *   tier        — 'free' | 'registered' | 'free+registered'
     *   roles       — opcional, override do tier. Array de roles que podem
     *                 ver o template. Se omitido, usa o tier padrão.
     *
     * IMPORTANTE: `bg` aponta para tokens de cor CSS já definidos em
     * style.css (Issue #126). O `fg` (cor do ícone) é sempre `var(--bg-deep)`
     * para garantir contraste sobre o bg colorido.
     */
    const TEMPLATES = Object.freeze([
        {
            id: 'blank',
            label: 'Em branco',
            desc: 'Comece do zero — sem entidade raiz.',
            icon: 'file-plus',
            bg: 'var(--text-faint)',
            rootNode: null,
            transforms: [],
            tier: 'none',
        },
        {
            id: 'person-osint',
            label: 'Pessoa (OSINT)',
            desc: 'Investigação de pessoa física: e-mail, breaches e domínios.',
            icon: 'user-search',
            bg: 'var(--c-person)',
            rootNode: { type: 'Person', value: 'Nome a investigar' },
            transforms: [
                'email_to_domain',
                'hibp_breach_lookup',     // registered
                'person_domain_discovery', // registered
            ],
            tier: 'registered',
        },
        {
            id: 'company-investigation',
            label: 'Empresa (CNPJ)',
            desc: 'Due diligence de empresa: domínios associados, contatos.',
            icon: 'building-2',
            bg: 'var(--c-empresa)',
            rootNode: { type: 'CNPJ', value: '00.000.000/0001-00' },
            transforms: [
                'email_to_domain',
                'hunter_domain_search', // registered
                'whois_lookup',
            ],
            tier: 'registered',
        },
        {
            id: 'network-recon',
            label: 'Recon de rede',
            desc: 'Domínio → DNS, WHOIS, GeoIP e reputação de IP.',
            icon: 'network',
            bg: 'var(--c-domain)',
            rootNode: { type: 'Domain', value: 'example.com' },
            transforms: [
                'reverse_dns',
                'whois_lookup',
                'dns_records_lookup',
                'geoip_lookup',
                'abuseipdb_lookup', // registered
            ],
            tier: 'free+registered',
        },
        {
            id: 'market-analysis',
            label: 'Análise de mercado',
            desc: 'Empresa + ticker, com IBAN/SWIFT e WHOIS de sites oficiais.',
            icon: 'line-chart',
            bg: 'var(--c-acao)',
            rootNode: { type: 'Acao', value: 'PETR4' },
            transforms: [
                'iban_swift_validation',
                'whois_lookup',
            ],
            tier: 'free',
        },
    ]);

    // ──────────── Gating de visibilidade ────────────

    /**
     * Decisão de role: se o template define `roles` (override), respeita
     * essa lista. Senão, deriva do `tier`:
     *   - 'free' / 'free+registered' / 'none' → todos os roles autenticados
     *   - 'registered'                        → roles com `investigation:create`
     *                                            (admin, analyst — fonte:
     *                                            OpenMPermissions.can)
     *
     * @param {object} user — user object retornado por OpenMAuth (precisa
     *                        ter `user.role` ou `user.tier`).
     * @returns {Array} subset de TEMPLATES visíveis para o user.
     */
    function getVisible(user) {
        // Fallback RBAC via OpenMPermissions quando disponível —
        // alinhamento com a matriz do backend (permissions.js).
        const canCreate = window.OpenMPermissions
            && typeof window.OpenMPermissions.can === 'function'
            ? window.OpenMPermissions.can(user && user.role, 'investigation:create')
            : (user && (user.role === 'admin' || user.role === 'analyst'));

        return TEMPLATES.filter((t) => {
            // Override explícito: roles array.
            if (Array.isArray(t.roles) && t.roles.length) {
                return t.roles.includes(user && user.role);
            }
            // Tier none: aparece sempre (mesmo para anônimo — usado pelo
            // shell antes do auth bootstrap).
            if (t.tier === 'none') return true;
            // Tier free: qualquer usuário autenticado.
            if (t.tier === 'free') return !!user;
            // Free+registered: usuário autenticado E com permissão de criar.
            if (t.tier === 'free+registered') return !!user && canCreate;
            // Registered: requer permissão de criar (admin/analyst).
            if (t.tier === 'registered') return canCreate;
            return true;
        });
    }

    // ──────────── UI: galeria de templates ────────────

    /**
     * Abre o `<wa-dialog>` com o grid de cards de templates. Auto-contido:
     * cria e destrói o dialog a cada chamada (sem estado residual).
     *
     * Click em um card:
     *   1. Pergunta título/descrição (Modal.confirm OU prompt inline WA).
     *   2. Cria investigation via OpenMAPI.createInvestigation.
     *   3. Se template.rootNode != null, cria a entidade raiz e (Lane 4B
     *      integrará) popula o canvas.
     *   4. Anuncia sucesso.
     */
    async function openGallery() {
        const ready = await _waitWaReady('wa-dialog');
        if (!ready) {
            if (window.App) window.App.setStatus('Componente de diálogo indisponível', 'error');
            return;
        }

        const user = (window.App && window.App.currentUser) || null;
        const visible = getVisible(user);

        // ── Markup do dialog ──
        const root = document.getElementById('template-gallery-root') || (() => {
            const r = document.createElement('div');
            r.id = 'template-gallery-root';
            document.body.appendChild(r);
            return r;
        })();

        const dialog = document.createElement('wa-dialog');
        dialog.id = 'template-gallery';
        dialog.setAttribute('label', 'Escolha um template');
        dialog.setAttribute('without-header', '');
        dialog.setAttribute('light-dismiss', '');
        dialog.style.setProperty('--width', '720px');
        dialog.classList.add('template-gallery');
        dialog.innerHTML = `
            <div class="tpl-gallery-header" slot="header">
                <h3 class="tpl-gallery-title">Escolha um template</h3>
                <button class="tpl-gallery-close" type="button" aria-label="Fechar galeria">
                    <i data-lucide="x" aria-hidden="true"></i>
                </button>
            </div>
            <div class="tpl-gallery-body">
                <p class="tpl-gallery-sub">Comece uma investigação a partir de um ponto de partida pré-configurado.</p>
                <div class="tpl-grid" role="list">
                    ${visible.map(_renderCard).join('')}
                </div>
            </div>
            <div class="tpl-gallery-footer" slot="footer">
                <button class="wa-button wa-button--text" data-action="cancel" type="button">Cancelar</button>
            </div>
        `;
        root.appendChild(dialog);

        // Lucide icons (ícone do close + ícones dos cards).
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            try { window.lucide.createIcons(); } catch (e) { /* silent */ }
        }

        // ── Listeners ──
        const close = () => {
            try { dialog.open = false; } catch (e) {
                if (typeof dialog.hide === 'function') dialog.hide();
            }
            // Cleanup após animação do WA.
            dialog.addEventListener('wa-after-hide', () => {
                if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
            }, { once: true });
        };

        dialog.querySelector('.tpl-gallery-close')?.addEventListener('click', close);
        dialog.querySelector('[data-action="cancel"]')?.addEventListener('click', close);
        dialog.addEventListener('wa-hide', () => {
            if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
        });

        // Click delegation: pega o card e dispara seleção.
        dialog.querySelector('.tpl-grid')?.addEventListener('click', (ev) => {
            const t = ev.target;
            if (!(t instanceof Element)) return;
            const card = t.closest('.tpl-card');
            if (!card) return;
            const id = card.getAttribute('data-template-id');
            if (!id) return;
            const tpl = TEMPLATES.find((x) => x.id === id);
            if (tpl) {
                close();
                _onSelect(tpl);
            }
        });

        // ── Open ──
        try { dialog.open = true; }
        catch (e) { if (typeof dialog.show === 'function') dialog.show(); }
    }

    /**
     * Renderiza o markup de um card. Mantido como função pura para
     * reuso (futuro: re-render ao mudar role).
     */
    function _renderCard(tpl) {
        const tierLabel = _tierLabel(tpl.tier);
        const escapeAttr = (s) => String(s).replace(/"/g, '&quot;');
        return `
            <button class="tpl-card" type="button" role="listitem"
                data-template-id="${escapeAttr(tpl.id)}"
                aria-label="${escapeAttr(tpl.label)} — ${escapeAttr(tpl.desc)}">
                <span class="tpl-icon" style="background: ${tpl.bg};" aria-hidden="true">
                    <i data-lucide="${escapeAttr(tpl.icon)}" style="color: var(--bg-deep);"></i>
                </span>
                <span class="tpl-text">
                    <span class="tpl-label">${escapeHtml(tpl.label)}</span>
                    <span class="tpl-desc">${escapeHtml(tpl.desc)}</span>
                    ${tierLabel ? `<span class="tpl-tier">${escapeHtml(tierLabel)}</span>` : ''}
                </span>
            </button>
        `;
    }

    function _tierLabel(tier) {
        switch (tier) {
            case 'free': return 'Grátis';
            case 'registered': return 'Conta requerida';
            case 'free+registered': return 'Recomendado';
            case 'none': return '';
            default: return '';
        }
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // ──────────── Seleção: prompt + criação ────────────

    /**
     * Ao clicar num card, perguntamos título/descrição via um sub-dialog
     * WA (não dependemos de Modal.prompt porque o `modals.js` atual só
     * expõe `confirm`). Após confirmar, criamos a investigation e a
     * entidade raiz (se houver).
     */
    async function _onSelect(tpl) {
        const title = await _promptText(
            `Investigation — ${tpl.label}`,
            'Título da investigation',
            tpl.rootNode ? `${tpl.label}: ${tpl.rootNode.value}` : tpl.label,
            'Descrição (opcional)',
            '',
        );
        if (!title) return; // usuário cancelou

        try {
            if (window.App) window.App.setStatus('Criando investigation...', 'info');

            // 1) Cria investigation via API direta (não dependemos de
            //    App.createInvestigation que hoje lê do DOM — Lane 4B
            //    pode unificar).
            const result = await window.OpenMAPI.createInvestigation(title.value, title.description || '', null);
            const inv = result && (result.investigation || result);
            const invId = inv && inv.id;

            // 2) Se template tem rootNode, cria a entidade e (idealmente)
            //    vincula à investigation. Aqui chamamos App.createEntity
            //    se disponível — o backend de createEntity do OpenM já
            //    associa à investigation ativa via cookie/sessão; se a
            //    nova investigation precisar ser a ativa, a Lane 4B
            //    deve injetar isso.
            if (tpl.rootNode && window.App && typeof window.App.createEntity === 'function') {
                try {
                    await window.App.createEntity(tpl.rootNode.type, tpl.rootNode.value);
                } catch (e) {
                    // Não bloqueia a criação da investigation.
                    console.warn('[OpenMTemplates] falha ao criar rootNode:', e);
                }
            }

            // 3) Recarrega a lista e anuncia.
            if (window.App && typeof window.App.loadInvestigations === 'function') {
                try { await window.App.loadInvestigations(); } catch (e) { /* silent */ }
            }

            if (window.App && typeof window.App.announce === 'function') {
                window.App.announce(
                    `Investigation "${title.value}" criada com template ${tpl.label}`,
                    'polite',
                );
            }
            if (window.App) window.App.setStatus(`✓ Investigation "${title.value}" criada`, 'success');
        } catch (err) {
            console.error('[OpenMTemplates] erro ao criar investigation:', err);
            if (window.App) window.App.setStatus(err.message || 'Erro ao criar investigation', 'error');
        }
    }

    /**
     * Pequeno prompt de texto (título + descrição) usando `<wa-dialog>`.
     * Retorna `{ value, description }` ou `null` se cancelado.
     */
    function _promptText(dialogTitle, label, defaultValue = '', descLabel = '', defaultDesc = '') {
        return new Promise((resolve) => {
            const ready = _waitWaReady('wa-dialog').then((ok) => {
                if (!ok) { resolve(null); return; }
                const host = document.createElement('div');
                document.body.appendChild(host);
                const d = document.createElement('wa-dialog');
                d.setAttribute('label', dialogTitle);
                d.setAttribute('light-dismiss', '');
                d.style.setProperty('--width', '420px');
                d.innerHTML = `
                    <div class="tpl-prompt-body">
                        <label class="tpl-prompt-label" for="tpl-prompt-title">${escapeHtml(label)}</label>
                        <wa-input id="tpl-prompt-title" value="${escapeHtml(defaultValue)}" required></wa-input>
                        <label class="tpl-prompt-label" for="tpl-prompt-desc">${escapeHtml(descLabel)}</label>
                        <wa-textarea id="tpl-prompt-desc" value="${escapeHtml(defaultDesc)}" rows="2"></wa-textarea>
                    </div>
                    <div slot="footer" class="tpl-prompt-footer">
                        <button class="wa-button wa-button--text" data-action="cancel" type="button">Cancelar</button>
                        <button class="wa-button wa-button--brand" data-action="ok" type="button">Criar</button>
                    </div>
                `;
                host.appendChild(d);

                const cleanup = () => {
                    try { d.open = false; } catch (e) { /* silent */ }
                    d.addEventListener('wa-after-hide', () => {
                        if (host.parentNode) host.parentNode.removeChild(host);
                    }, { once: true });
                };

                d.querySelector('[data-action="cancel"]')?.addEventListener('click', () => {
                    cleanup();
                    resolve(null);
                });
                d.querySelector('[data-action="ok"]')?.addEventListener('click', () => {
                    const value = d.querySelector('#tpl-prompt-title')?.value?.trim()
                        || defaultValue.trim();
                    const description = d.querySelector('#tpl-prompt-desc')?.value?.trim() || '';
                    if (!value) {
                        if (window.App) window.App.setStatus('Título é obrigatório', 'error');
                        return;
                    }
                    cleanup();
                    resolve({ value, description });
                });
                d.addEventListener('wa-hide', () => {
                    // Resolve null quando o usuário fecha com ESC.
                    resolve(null);
                });

                try { d.open = true; }
                catch (e) { if (typeof d.show === 'function') d.show(); }

                // Foco inicial no input.
                requestAnimationFrame(() => {
                    const input = d.querySelector('#tpl-prompt-title');
                    if (input && typeof input.focus === 'function') input.focus();
                });
            });
            // Se WA nunca carregar, nunca resolve — caller trata como cancel.
            void ready;
        });
    }

    // ──────────── WA ready helper local ────────────

    function _waReady(tag) {
        return typeof window !== 'undefined'
            && !!window.customElements
            && customElements.get(tag) !== undefined;
    }
    function _waitWaReady(tag) {
        return new Promise((resolve) => {
            if (_waReady(tag)) { resolve(true); return; }
            const start = Date.now();
            const id = setInterval(() => {
                if (_waReady(tag)) { clearInterval(id); resolve(true); }
                else if (Date.now() - start > 3000) { clearInterval(id); resolve(false); }
            }, 50);
        });
    }

    // ──────────── Exposição ────────────

    window.OpenMTemplates = {
        TEMPLATES,
        getVisible,
        openGallery,
    };
})();
