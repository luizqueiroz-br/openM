/**
 * Command Palette — registro de comandos (issue #133).
 *
 * Este arquivo define **apenas os dados**: 36+ comandos agrupados em 6
 * categorias, com gating por role via `OpenMPermissions.can()`. A UI (o
 * `<dialog>`) é gerenciada por `command-palette.js` (consumidor).
 *
 * Namespace exportado: `window.CommandPalette`.
 *
 * Convenções:
 *   - Não há build step. ES2020+ é OK (Chrome/Firefox/Safari recentes).
 *   - PT-BR em `label`, `hint` e mensagens. Atalhos e IDs em EN.
 *   - Cada `run()` é defensivo: checa se a função existe antes de
 *     chamar e usa `App.announce()` em sucesso/erro para screen readers.
 *   - `CommandPalette.init()` NÃO é chamado automaticamente — o entry
 *     é `App.init()` (em app.js) que conhece a ordem de bootstrap.
 */
(function () {
    'use strict';

    // ============ Helpers de atalho/anúncio ============

    function announce(message, priority) {
        if (window.App && typeof window.App.announce === 'function') {
            window.App.announce(message, priority || 'polite');
        }
    }

    function runIf(fn, label) {
        if (typeof fn === 'function') {
            try {
                fn();
                announce(label + ' executado', 'polite');
            } catch (err) {
                console.error('[CommandPalette] erro em', label, err);
                announce('Falha ao executar ' + label, 'assertive');
            }
        } else {
            announce('Ação indisponível: ' + label, 'assertive');
        }
    }

    function toast(message) {
        // Placeholder: reusa o padrão de toast do app via announce.
        announce(message, 'polite');
    }

    // ============ Comandos (36) ============

    const COMMANDS = [
        // ─────────── Navegação (6) ───────────
        {
            id: 'nav.tab.entities',
            label: 'Ir para Entidades',
            hint: 'Mostra a paleta de entidades arrastáveis',
            category: 'Navegação',
            shortcut: '⌘1',
            icon: 'shapes',
            run: () => runIf(() => window.App && window.App.setActiveSidebarTab('palette'), 'Ir para Entidades'),
        },
        {
            id: 'nav.tab.investigations',
            label: 'Ir para Investigações',
            hint: 'Lista de investigações salvas',
            category: 'Navegação',
            shortcut: '⌘2',
            icon: 'folder-open',
            run: () => runIf(() => window.App && window.App.setActiveSidebarTab('investigations'), 'Ir para Investigações'),
        },
        {
            id: 'nav.tab.transforms',
            label: 'Ir para Transforms',
            hint: 'Catálogo de transforms disponíveis',
            category: 'Navegação',
            shortcut: '⌘3',
            icon: 'workflow',
            roles: ['transform:run'],
            run: () => {
                runIf(() => window.App && window.App.setActiveSidebarTab('transforms'), 'Ir para Transforms');
            },
        },
        {
            id: 'nav.tab.admin',
            label: 'Ir para Admin',
            hint: 'Gerenciamento de usuários e API keys',
            category: 'Navegação',
            icon: 'shield',
            roles: ['user:list'],
            run: () => runIf(() => window.App && window.App.setActiveSidebarTab('admin'), 'Ir para Admin'),
        },
        {
            id: 'nav.toggle-sidebar',
            label: 'Alternar sidebar',
            hint: 'Mostra ou esconde a barra lateral esquerda',
            category: 'Navegação',
            shortcut: '⌘B',
            icon: 'panel-left',
            run: () => runIf(() => window.App && window.App.toggleSidebar(), 'Alternar sidebar'),
        },
        {
            id: 'nav.toggle-inspector',
            label: 'Alternar inspector',
            hint: 'Mostra ou esconde o painel de detalhes',
            category: 'Navegação',
            shortcut: '⌘I',
            icon: 'panel-right',
            run: () => runIf(() => window.App && window.App.toggleInspector(), 'Alternar inspector'),
        },

        // ─────────── Painel (4) ───────────
        {
            id: 'panel.open-search',
            label: 'Abrir busca do grafo',
            hint: 'Painel de busca e filtros do grafo',
            category: 'Painel',
            shortcut: '⌘F',
            icon: 'search',
            run: () => runIf(() => window.SearchPanel && window.SearchPanel.toggle(), 'Abrir busca do grafo'),
        },
        {
            id: 'panel.close-search',
            label: 'Fechar busca do grafo',
            hint: 'Esconde o painel de busca',
            category: 'Painel',
            icon: 'x',
            run: () => runIf(() => window.SearchPanel && window.SearchPanel.close(), 'Fechar busca do grafo'),
        },
        {
            id: 'panel.focus-palette-input',
            label: 'Focar busca da paleta',
            hint: 'Move o cursor para o campo de busca',
            category: 'Painel',
            icon: 'mouse-pointer-click',
            run: () => {
                const input = document.getElementById('cp-input');
                if (input) {
                    input.focus();
                    announce('Campo de busca focado', 'polite');
                } else {
                    announce('Campo de busca indisponível', 'assertive');
                }
            },
        },
        {
            id: 'panel.clear-filters',
            label: 'Limpar filtros do grafo',
            hint: 'Desseleciona todos os filtros de tipo',
            category: 'Painel',
            icon: 'filter-x',
            run: () => {
                if (window.SearchPanel && typeof window.SearchPanel.getState === 'function') {
                    const state = window.SearchPanel.getState();
                    if (state && state.hiddenTypes) {
                        state.hiddenTypes.clear();
                        if (typeof window.SearchPanel.apply === 'function') {
                            window.SearchPanel.apply();
                        }
                        announce('Filtros limpos', 'polite');
                        return;
                    }
                }
                toast('Filtros limpos');
            },
        },

        // ─────────── Grafo (8) ───────────
        {
            id: 'graph.fit',
            label: 'Centralizar grafo',
            hint: 'Ajusta a visualização para mostrar todos os elementos',
            category: 'Grafo',
            shortcut: 'F',
            icon: 'maximize',
            run: () => runIf(() => window.Graph && window.Graph.fit(), 'Centralizar grafo'),
        },
        {
            id: 'graph.relayout',
            label: 'Reorganizar layout',
            hint: 'Aplica layout grid novamente',
            category: 'Grafo',
            icon: 'layout-grid',
            run: () => runIf(() => window.Graph && window.Graph.relayout(), 'Reorganizar layout'),
        },
        {
            id: 'graph.undo',
            label: 'Desfazer',
            hint: 'Reverte a última ação no grafo',
            category: 'Grafo',
            shortcut: '⌘Z',
            icon: 'undo-2',
            roles: ['entity:create'],
            run: () => runIf(() => window.Graph && window.Graph.undo(), 'Desfazer'),
        },
        {
            id: 'graph.redo',
            label: 'Refazer',
            hint: 'Refaz a última ação desfeita',
            category: 'Grafo',
            shortcut: '⌘Y',
            icon: 'redo-2',
            roles: ['entity:create'],
            run: () => runIf(() => window.Graph && window.Graph.redo(), 'Refazer'),
        },
        {
            id: 'graph.clear',
            label: 'Limpar grafo',
            hint: 'Remove todos os elementos do canvas',
            category: 'Grafo',
            icon: 'trash',
            roles: ['entity:create'],
            run: () => {
                if (window.Modal && typeof window.Modal.confirm === 'function') {
                    window.Modal.confirm({
                        title: 'Limpar grafo?',
                        message: 'Esta ação removerá todas as entidades e arestas do canvas.',
                        danger: true,
                        onConfirm: () => {
                            runIf(() => window.Graph && window.Graph.clear(), 'Limpar grafo');
                        },
                    });
                } else {
                    runIf(() => window.Graph && window.Graph.clear(), 'Limpar grafo');
                }
            },
        },
        {
            id: 'graph.export',
            label: 'Exportar grafo',
            hint: 'Baixa JSON com entidades e arestas',
            category: 'Grafo',
            icon: 'download',
            run: () => runIf(() => window.App && window.App.exportGraph(), 'Exportar grafo'),
        },
        {
            id: 'graph.import',
            label: 'Importar grafo',
            hint: 'Carrega JSON e substitui o canvas',
            category: 'Grafo',
            icon: 'upload',
            roles: ['entity:create'],
            run: () => runIf(() => window.App && window.App.importGraph(), 'Importar grafo'),
        },
        {
            id: 'graph.focus-selected',
            label: 'Focar seleção',
            hint: 'Centraliza o grafo no elemento selecionado',
            category: 'Grafo',
            shortcut: 'F',
            icon: 'crosshair',
            run: () => {
                if (window.Graph && window.Graph.selected) {
                    runIf(() => window.Graph.fit(), 'Focar seleção');
                } else {
                    announce('Nenhum elemento selecionado', 'assertive');
                }
            },
        },

        // ─────────── Investigação (6) ───────────
        {
            id: 'inv.new',
            label: 'Nova investigação',
            hint: 'Cria uma investigação em branco',
            category: 'Investigação',
            icon: 'plus-circle',
            roles: ['investigation:create'],
            run: () => runIf(() => window.App && window.App.createInvestigation(), 'Nova investigação'),
        },
        {
            id: 'inv.save',
            label: 'Salvar investigação',
            hint: 'Persiste o estado atual do canvas',
            category: 'Investigação',
            shortcut: '⌘S',
            icon: 'save',
            run: () => runIf(() => window.App && window.App.saveInvestigation(), 'Salvar investigação'),
        },
        {
            id: 'inv.refresh',
            label: 'Recarregar investigações',
            hint: 'Atualiza a lista de investigações',
            category: 'Investigação',
            icon: 'refresh-cw',
            run: () => runIf(() => window.App && window.App.loadInvestigations(), 'Recarregar investigações'),
        },
        {
            id: 'inv.archive-selected',
            label: 'Arquivar selecionada',
            hint: 'Move a investigação atual para arquivo',
            category: 'Investigação',
            icon: 'archive',
            roles: ['investigation:archive'],
            run: () => {
                if (window.Modal && typeof window.Modal.confirm === 'function') {
                    window.Modal.confirm({
                        title: 'Arquivar investigação?',
                        message: 'A investigação ficará oculta da lista principal.',
                        danger: false,
                        onConfirm: () => toast('Arquivamento solicitado (placeholder)'),
                    });
                } else {
                    toast('Arquivamento solicitado (placeholder)');
                }
            },
        },
        {
            id: 'inv.delete-selected',
            label: 'Excluir selecionada',
            hint: 'Remove a investigação atual permanentemente',
            category: 'Investigação',
            icon: 'trash-2',
            roles: ['investigation:create'],
            run: () => {
                if (window.Modal && typeof window.Modal.confirm === 'function') {
                    window.Modal.confirm({
                        title: 'Excluir investigação?',
                        message: 'Esta ação não pode ser desfeita.',
                        danger: true,
                        onConfirm: () => toast('Exclusão solicitada (placeholder)'),
                    });
                } else {
                    toast('Exclusão solicitada (placeholder)');
                }
            },
        },
        {
            id: 'inv.open-recent',
            label: 'Abrir investigação recente',
            hint: 'Pula para a última investigação modificada',
            category: 'Investigação',
            icon: 'history',
            run: () => toast('Nenhuma investigação recente disponível'),
        },

        // ─────────── Tema (3) ───────────
        {
            id: 'theme.toggle',
            label: 'Alternar tema',
            hint: 'Claro ↔ escuro',
            category: 'Tema',
            shortcut: '⌘⇧T',
            icon: 'contrast',
            run: () => runIf(() => window.App && window.App.toggleTheme(), 'Alternar tema'),
        },
        {
            id: 'theme.set-dark',
            label: 'Tema escuro',
            hint: 'Ativa o modo escuro',
            category: 'Tema',
            icon: 'moon',
            run: () => runIf(() => window.App && window.App.setTheme('dark', true), 'Tema escuro'),
        },
        {
            id: 'theme.set-light',
            label: 'Tema claro',
            hint: 'Ativa o modo claro',
            category: 'Tema',
            icon: 'sun',
            run: () => runIf(() => window.App && window.App.setTheme('light', true), 'Tema claro'),
        },

        // ─────────── Transforms (5) ───────────
        {
            id: 'transforms.run-last',
            label: 'Re-rodar último transform',
            hint: 'Executa novamente o último transform selecionado',
            category: 'Transforms',
            shortcut: '⌘⇧R',
            icon: 'play',
            roles: ['transform:run'],
            run: () => runIf(() => window.TransformHub && window.TransformHub.runLastTransform(), 'Re-rodar último transform'),
        },
        {
            id: 'transforms.run-all-on-selected',
            label: 'Rodar todos os transforms no selecionado',
            hint: 'Executa todos os transforms disponíveis no nó',
            category: 'Transforms',
            icon: 'zap',
            roles: ['transform:run'],
            run: () => {
                if (window.Graph && window.Graph.selected && window.Graph.selected.isNode && window.Graph.selected.isNode()) {
                    runIf(() => window.App && window.App.runAllTransforms(window.Graph.selected), 'Rodar todos os transforms');
                } else {
                    announce('Selecione um nó antes de rodar transforms', 'assertive');
                }
            },
        },
        {
            id: 'transforms.open-hub',
            label: 'Abrir hub de transforms',
            hint: 'Mostra o painel lateral de transforms',
            category: 'Transforms',
            shortcut: '⌘3',
            icon: 'workflow',
            roles: ['transform:run'],
            run: () => runIf(() => window.App && window.App.setActiveSidebarTab('transforms'), 'Abrir hub de transforms'),
        },
        {
            id: 'transforms.list',
            label: 'Listar transforms',
            hint: 'Em breve: lista detalhada com descrições',
            category: 'Transforms',
            icon: 'list',
            run: () => toast('Listagem detalhada em construção'),
        },
        {
            id: 'transforms.metrics',
            label: 'Métricas de transforms',
            hint: 'Estatísticas de execução',
            category: 'Transforms',
            icon: 'bar-chart-3',
            run: () => toast('Métricas em construção'),
        },

        // ─────────── Ajuda (4) ───────────
        {
            id: 'help.shortcuts',
            label: 'Ver atalhos de teclado',
            hint: 'Abre o overlay de atalhos',
            category: 'Ajuda',
            shortcut: '?',
            icon: 'keyboard',
            run: () => {
                document.dispatchEvent(new CustomEvent('openm:open-shortcuts'));
                announce('Atalhos abertos', 'polite');
            },
        },
        {
            id: 'help.open-docs',
            label: 'Abrir documentação',
            hint: 'Abre a documentação em nova aba',
            category: 'Ajuda',
            icon: 'book-open',
            run: () => {
                try {
                    window.open('/docs', '_blank', 'noopener,noreferrer');
                } catch (e) {
                    window.location.href = '/docs';
                }
            },
        },
        {
            id: 'help.about',
            label: 'Sobre o OpenM',
            hint: 'Informações da versão',
            category: 'Ajuda',
            icon: 'info',
            run: () => toast('OpenM — OSINT Made Open'),
        },
        {
            id: 'help.feedback',
            label: 'Reportar problema',
            hint: 'Abre o repositório no GitHub',
            category: 'Ajuda',
            icon: 'bug',
            run: () => {
                try {
                    window.open('https://github.com/luizqueiroz-br/openM/issues', '_blank', 'noopener,noreferrer');
                } catch (e) {
                    window.location.href = 'https://github.com/luizqueiroz-br/openM/issues';
                }
            },
        },
        {
            // Issue #134: replay do onboarding tour de 5 passos.
            // Visível para todos (mesmo padrão dos outros comandos de Ajuda).
            // O `force: true` ignora localStorage.openm.tour.onboarding.completed.
            id: 'help.replay-tour',
            label: 'Replay do tour guiado',
            hint: 'Roda novamente o tour de 5 passos',
            category: 'Ajuda',
            icon: 'compass',
            run: () => {
                if (window.OpenMTour && typeof window.OpenMTour.start === 'function') {
                    window.OpenMTour.start({ force: true });
                } else if (window.App && window.App.announce) {
                    window.App.announce('Tour não disponível', 'assertive');
                }
            },
        },
    ];

    // ============ Categorias canônicas (ordem de exibição) ============

    const CATEGORIES = [
        'Navegação',
        'Painel',
        'Grafo',
        'Investigação',
        'Tema',
        'Transforms',
        'Ajuda',
    ];

    // ============ Filtros / Gating ============

    /**
     * Decide se um comando é visível para o usuário.
     * Sem `cmd.roles` → sempre visível.
     * Com `cmd.roles` → exige que `OpenMPermissions.can(role, action)` retorne true
     * para **pelo menos uma** das actions.
     */
    function visible(cmd, user) {
        if (!cmd || !cmd.roles || cmd.roles.length === 0) return true;
        if (!user || !user.role) return false;
        const perms = window.OpenMPermissions;
        if (!perms || typeof perms.can !== 'function') {
            // Sem permissões carregadas, falha fechado: só mostra o que não tem role.
            return false;
        }
        return cmd.roles.some((action) => perms.can(user.role, action));
    }

    /**
     * Retorna os comandos visíveis para o usuário atual.
     * Cached: rebuild só se a referência de `user` mudar.
     */
    let _cache = { user: null, list: null };
    function visibleCommands(user) {
        if (_cache.user === user && _cache.list) return _cache.list;
        const list = COMMANDS.filter((c) => visible(c, user));
        _cache = { user, list };
        return list;
    }

    /**
     * Constrói (ou reusa) um índice Fuse sobre os comandos visíveis.
     */
    let _fuse = null;
    let _fuseUser = null;
    function buildIndex(user) {
        if (_fuse && _fuseUser === user) return _fuse;
        const list = visibleCommands(user);
        if (!window.Fuse) {
            console.warn('[CommandPalette] Fuse não carregado; busca ficará desabilitada');
            _fuse = null;
            _fuseUser = user;
            return null;
        }
        _fuse = new window.Fuse(list, {
            keys: ['label', 'hint', 'category'],
            threshold: 0.4,
            ignoreLocation: true,
            minMatchCharLength: 1,
        });
        _fuseUser = user;
        return _fuse;
    }

    /**
     * Executa um comando pelo id. Anuncia sucesso/erro via App.announce.
     */
    function run(id) {
        const cmd = COMMANDS.find((c) => c.id === id);
        if (!cmd) {
            announce('Comando não encontrado: ' + id, 'assertive');
            return false;
        }
        if (!visible(cmd, window.App && window.App.currentUser)) {
            announce('Sem permissão para: ' + cmd.label, 'assertive');
            return false;
        }
        try {
            cmd.run();
            return true;
        } catch (err) {
            console.error('[CommandPalette] erro em', id, err);
            announce('Falha ao executar ' + cmd.label, 'assertive');
            return false;
        }
    }

    /**
     * Inicialização preguiçosa. Pode ser chamada mais de uma vez.
     */
    function init() {
        // Nada a fazer no momento — tudo é resolvido on-demand.
        // Mantido para simetria com os outros módulos e para que
        // App.init() tenha um ponto claro de bootstrap.
    }

    // ============ Export ============

    window.CommandPalette = {
        init,
        open: () => window.CommandPaletteUI && window.CommandPaletteUI.open(),
        close: () => window.CommandPaletteUI && window.CommandPaletteUI.close(),
        toggle: () => window.CommandPaletteUI && window.CommandPaletteUI.toggle(),
        run,
        buildIndex,
        getCommands: () => visibleCommands(window.App && window.App.currentUser),
        getCategories: () => CATEGORIES.slice(),
        visible,
    };
})();
