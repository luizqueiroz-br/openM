# Issues — Frontend Redesign (OpenM)

> **Status:** Rascunho para revisão. Não publicado no GitHub ainda.
> **Estratégia:** 11 issues definitivas (4 fases) + 5 adiadas (v2+).
> **Validação prévia:** discovery (estrutura), librarian (libs e padrões), designer (sistema de design), oracle (priorização).

---

## Sumário executivo

O OpenM tem hoje um frontend vanilla JS funcional mas com 15 gaps de UX conhecidos: zero responsividade, zero acessibilidade, zero toasts, sem mini-map, sem busca no grafo, sem export PNG/SVG, sem dark/light toggle, sem atalhos documentados. O redesign ataca esses gaps em **4 fases** (~7.5 semanas) preservando a arquitetura vanilla (sem build step, sem React/Vue) e adotando Web Components (Web Awesome 3.9+).

**Marcos**:
- `v1.0-frontend "Tema"` (Phase 1+2): 3.5 semanas — quick wins + design system + a11y
- `v1.1-frontend "OSINT"` (Phase 3): +2.5 semanas — Inspector 3-tabs + Transform Hub + Search
- `v1.1.x-frontend "Mobile"` (Phase 4): +1.5 semanas — responsividade + command palette + onboarding

**Recomendação operacional do oracle**: começar pela **Issue D (Design System & Theming)** ainda esta semana, mesmo antes de finalizar este plano, para validar `oklch()` e Safari <16.4 antes de gastar tempo em issues detalhadas.

---

## Convenções

### Restrições inegociáveis (preservar)
- **Sem build step** (sem Vite/esbuild/webpack/Rollup) — única exceção: bundler CSS se monolítico passar de 2000 linhas.
- **Sem React/Vue/Svelte** — componentização via Web Components (Web Awesome) + vanilla JS.
- **Sem Tailwind CDN** (estilo atual é melhor).
- **Sem CSS-in-JS runtime** — CSS vars + custom properties em `oklch()`.
- **Manter Cytoscape.js** (atualizar 3.26 → 3.31.1; NÃO migrar para Sigma.js/G6/Reagraph/react-flow).
- **Manter padrão `window.*`** (NÃO refatorar para ES modules até entrar build step).

### Stack de libs UI aprovada (~70 KB total gzipped)
- **Web Awesome 3.9+** (MIT, Web Components, CDN, dark/light nativo, ARIA built-in) — design system
- **Notyf 3.x** (MIT, 3 KB) — toasts
- **Fuse.js 7.x** (ISC, ~6 KB) — busca fuzzy
- **hotkeys-js 4.0.3** (MIT, ~10 KB) — atalhos
- **cmdk-wc 1.x** (MIT, ~15 KB) — command palette (opcional, Phase 4)
- **Lucide** (ISC, 1-2 KB inline) — ícones (substituir Font Awesome 6.5.1)
- **Cytoscape 3.31.1** + navigator 4.0.1 + panzoom 2.5.3 + fcose 2.2.0 + undo-redo 1.3.3 + popper 2.0.x — plugins grafo

### Padrões OSINT consolidados (do benchmark Maltego/Kestrel/Spiderfoot/Linkurious/Cytoscape Desktop)
1. **Detail view 3-tabs** (Overview / Properties / Sightings) — convergência Maltego + Kestrel + Linkurious
2. **Transform Hub em árvore** com busca + filtros — Maltego Transform Hub
3. **Mini-map sempre visível** + auto-fit on layout change — Cytoscape Desktop + Gephi
4. **Timeline de eventos/Sightings** — Linkurious + Hunchly
5. **Canvas 4 modes** (V/H/N/E) com atalhos — Cytoscape Desktop

### Labels novos sugeridos
- `area:frontend` (já existe)
- `data:pf` / `data:pj` (reaproveitar do v1.0-brazil)
- `a11y:wcag-aa` (novo, para issues de acessibilidade)
- `perf:critical` (novo, para issues que tocam performance do grafo)
- `theme:dark` / `theme:light` (novo, para issues de tema)
- `breaking:visual` (novo, para issues que mudam aparência/UX de feature existente)
- `i18n:pt-br` (reaproveitar)
- `fixtures:required` (reaproveitar)

---

## Phase 1 — Quick wins visíveis (3 issues, ~1.5 semanas)

Release: `v1.0-frontend "Grafo+"`.

---

### Issue A — Canvas upgrade (Cytoscape 3.31 + plugins + export)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `breaking:visual`, `perf:critical`.

#### Resumo
Atualizar Cytoscape.js 3.26.0 → 3.31.1 (zero breaking, ganha WebGL preview opt-in + TS types) e adicionar 4 plugins: `cytoscape-fcose` (layout force-directed moderno, substitui cose-bilkent), `cytoscape-navigator` (mini-map), `cytoscape-panzoom` (controles visuais +/-/fit), export PNG/SVG via `cy.png()` nativo. Adicionar botão na topbar para cada feature.

#### Motivação
Mini-map é o pedido OSINT #1 (grafos >50 nós são cegos sem overview). `fcose` é mais rápido e estável que cose-bilkent. Export PNG é nativo (`cy.png()`) e Maltego faz. Cytoscape 3.26 → 3.31 é drop-in.

#### Solução proposta
- `openm/frontend/templates/index.html:17-20`: trocar URL do Cytoscape para `3.31.1` via CDN; adicionar 4 scripts dos plugins.
- `openm/frontend/static/js/graph.js:14-18`: registrar plugins (`cy.use(cytoscapeFcose)`, `cy.use(cytoscapeNavigator)`, etc.).
- `openm/frontend/static/js/graph.js:_buildStyle` (L50-164): adicionar style para mini-map container (canto inferior direito, 200x150px, 50% opacity).
- `openm/frontend/static/js/graph.js:relayout` (L504-521): trocar `cose-bilkent` por `fcose` com config compatível.
- `openm/frontend/static/js/graph.js`: adicionar método `exportPng()` e `exportSvg()` que chamam `cy.png({...})` e criam `<a download>`.
- `openm/frontend/templates/index.html:33-36` (canvas-overlay): adicionar botões "Mini-map" (toggle), "Export PNG", "Export SVG".
- `openm/frontend/static/css/style.css`: styles para mini-map (z-index alto, drag handle, resize handle opcional).

#### Critérios de aceitação
- [ ] Cytoscape 3.31.1 carregado do CDN
- [ ] `fcose` como layout default (fallback `grid` se falhar)
- [ ] Mini-map visível por padrão em grafos >10 nodes (toggle com botão M)
- [ ] Export PNG gera arquivo `.png` baixado
- [ ] Export SVG gera arquivo `.svg` baixado
- [ ] Sem regressão nos 7 transforms existentes
- [ ] Testes manuais em Chrome/Firefox/Safari 16.4+

#### Esforço
1 (2-3h).

#### Dependências
Nenhuma. Issue pré-requisito para a Phase 3 (Inspector 3-tabs depende do mini-map como referencial visual).

---

### Issue B — Sistema de Toasts (Notyf)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `breaking:visual`.

#### Resumo
Adicionar **Notyf 3.x** (3 KB, MIT) via CDN. Substituir o sistema atual de statusbar efêmero (`App.setStatus` em `app.js:235-241`) por toasts empilhados (max 5, canto inferior direito desktop / bottom-center mobile). 5 tipos: success, error, warning, info, loading. Toasts error e loading são sticky (auto-dismiss só após ação). Adaptar todas as 35+ chamadas a `setStatus` em `app.js` para usar o novo helper `App.toast(type, title, description)`.

#### Motivação
Statusbar de 1 linha compartilhada vira gargalo quando há múltiplos eventos (transform rodando + save + conflict). Toasts empilhados com ícones e cores melhoram feedback em 5x.

#### Solução proposta
- `openm/frontend/templates/index.html`: adicionar `<script src="https://cdn.jsdelivr.net/npm/notyf@3/notyf.min.js">` + `<link href="...notyf.min.css">`.
- `openm/frontend/static/js/app.js:235-241`: novo método `App.toast(type, title, description, opts)` que wraps Notyf.
- `openm/frontend/static/js/app.js`: em todos os pontos de chamada de `setStatus` (35+), mapear para `App.toast` apropriado:
  - Save success → toast success
  - Save failure → toast error sticky
  - Transform started → toast loading
  - Transform completed → toast success (dismiss loading)
  - Transform failed → toast error sticky com retry button
  - 401/403 → toast warning
  - Confirmação de delete → modal (NÃO toast)
- `openm/frontend/static/css/style.css`: customização do Notyf (cores conforme paleta de tokens, posição, duração 4s success/info, 6s warning, sticky error).

#### Critérios de aceitação
- [ ] Notyf 3.x carregado e configurado com paleta do OpenM
- [ ] 5 tipos funcionando: success, error, warning, info, loading
- [ ] Empilhamento máximo 5 visíveis
- [ ] Posição bottom-right desktop, bottom-center mobile
- [ ] `prefers-reduced-motion` desabilita animação de slide-in
- [ ] Todas as 35+ chamadas a `setStatus` migradas
- [ ] ARIA live region: anúncios de screen reader (polite para success/info, assertive para error)
- [ ] Documentação PT-BR em `docs/frontend-toasts.md`

#### Esforço
1 (4-6h).

#### Dependências
Nenhuma.

---

### Issue C — Undo/Redo expandido (cytoscape-undo-redo)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `breaking:visual`.

#### Resumo
Substituir lógica custom de undo/redo em `graph.js:573-591` (cap 50, redo apagada por nova ação, só cobre add_edge/remove_node/remove_edge) por **cytoscape-undo-redo 1.3.3** (Bilkent, MIT) que cobre todas as operações: `add_node`, `add_edge`, `remove_node`, `remove_edge`, `edit_property`, `set_style`, `move_node`, `group`. Stack com `{action, etag, payload}` para detectar conflitos com auto-save.

#### Motivação
Custom undo/redo é limitado e propenso a bugs (e.g., redo é apagada por qualquer pushUndo). Plugin oficial Bilkent cobre 90% dos casos e tem API estável. Usuário precisa confiar no grafo antes de adotar Inspector 3-tabs em Phase 3.

#### Solução proposta
- `openm/frontend/templates/index.html:18`: adicionar `cytoscape-undo-redo` script.
- `openm/frontend/static/js/graph.js:14-18`: `cy.use(cytoscapeUndoRedo)`.
- `openm/frontend/static/js/graph.js:573-591`: remover `pushUndo`/`undo`/`redo` custom; usar `ur.undo()`, `ur.redo()`, `ur.do(action)`.
- Adicionar adapter: `cy.on('add', 'node', ...)` → `ur.do('add', {nodes: [n]})`.
- Adicionar adapter: `cy.on('add', 'edge', ...)` → `ur.do('add', {edges: [e]})`.
- Adicionar adapter: `cy.on('remove', ...)` → `ur.do('remove', {...})`.
- Auto-save: `app.js:73` (AutoSave) — incluir `etag` no stack para rollback se conflito.
- `openm/frontend/static/js/app.js`: garantir que Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z continuam funcionando.

#### Critérios de aceitação
- [ ] Plugin `cytoscape-undo-redo` carregado e registrado
- [ ] `add_node`, `add_edge`, `remove_node`, `remove_edge`, `edit_property` cobrem undo/redo
- [ ] Stack persiste através de auto-save (sem perder ao salvar)
- [ ] Conflito de versão (If-Match 412) faz rollback automático com modal de resolução
- [ ] Testes com 2 abas abertas (consistência do stack)
- [ ] Sem regressão no auto-save existente

#### Esforço
2 (1-2 dias).

#### Dependências
Nenhuma.

---

## Phase 2 — Design System & Acessibilidade (3 issues, ~2 semanas)

Release: `v1.0.1-frontend "Tema"`. **Issue D é BLOQUEADOR de E e F**.

---

### Issue D — Design System & Theming (CSS tokens + dark/light + oklch)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `theme:dark`, `theme:light`, `breaking:visual`.

#### Resumo
Refatorar `openm/frontend/static/css/style.css` (1143 linhas) para usar **CSS custom properties em `oklch()`** com variantes light/dark via `[data-theme="dark|light"]` no `<html>`. Adicionar 14 tokens base (bg-deep, bg-panel, bg-card, bg-card-hover, bg-elev, border, border-strong, text, text-dim, text-faint, accent, accent-2, hot, success, warn, danger), 8 famílias de entity type (23 entidades) com 5 variantes cada (bg, fg, border, hot, soft), 5 famílias de edge, escala de espaçamento (11 tokens), tipografia (8 tamanhos), bordas (5 raios), sombras (4 níveis), focus ring, animações (5 durações + 4 easings) com `prefers-reduced-motion`. Adicionar toggle dark/light no topbar com persistência em `localStorage.openm.theme`.

#### Motivação
CSS monolítico atual usa hex hardcoded e rem orgânico — qualquer ajuste de tema vira busca-e-substitui em 1143 linhas. Tokens oklch permitem variação perceptual uniforme entre dark/light. Toggle dark/light é pedido de longa data (atualmente dark-only). Refactor é BLOQUEADOR: sem tokens, qualquer ajuste visual em Phase 3 custa 2x.

#### Solução proposta
- `openm/frontend/static/css/style.css` (1143 → ~1600 linhas estimadas):
  - Seção 1 (L1-200): `:root` com todos os tokens em `oklch()` (dark default) + `[data-theme="light"]` com overrides.
  - Seção 2 (L200-400): entity tokens (`--ent-{tipo}-bg/fg/border/hot/soft`) para 8 famílias × 23 entidades.
  - Seção 3 (L400-600): edge tokens (`--edge-{familia}` para parentesco/transação/regulatório/técnico/social).
  - Seção 4 (L600-800): refactor de todas as cores hex hardcoded para `var(--token)`.
  - Seção 5 (L800-1000): espaçamento, tipografia, borda, sombra, focus ring.
  - Seção 6 (L1000-1100): keyframes e transições com `prefers-reduced-motion` global.
  - Seção 7 (L1100-1200): estilos específicos (Cytoscape cxtmenu, modais, etc.) — manter.
- `openm/frontend/static/js/app.js`: adicionar `App.theme` (current) + `App.toggleTheme()` + listener de `prefers-color-scheme` para primeira visita.
- `openm/frontend/templates/index.html:33-36` (topbar): adicionar botão "Theme toggle" (ícone `sun` / `moon` Lucide).
- `openm/frontend/static/css/style.css`: regra global `@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; } }`.
- `docs/frontend-design-system.md` (novo): documentação dos tokens (referência para mantenedores).

#### Critérios de aceitação
- [ ] Todos os 14 tokens base em `oklch()` (dark default, light variant)
- [ ] 8 famílias de entity tokens × 23 entidades × 5 variantes
- [ ] 5 famílias de edge tokens
- [ ] Escala de espaçamento 11 tokens + 8 tokens compostos
- [ ] Tipografia com 8 tamanhos e line-heights
- [ ] Toggle dark/light funcional no topbar
- [ ] Persistência em `localStorage.openm.theme`
- [ ] Respeita `prefers-color-scheme` na primeira visita
- [ ] `prefers-reduced-motion` global desabilita animações
- [ ] Sem regressão visual em Chrome/Firefox/Safari 16.4+
- [ ] 100% das cores hex hardcoded substituídas por `var(--token)`
- [ ] Documentação PT-BR em `docs/frontend-design-system.md`

#### Esforço
4 (1 semana). **Issue BLOQUEADORA de E e F.**

#### Dependências
Nenhuma. Mas é bloqueadora de E e F (que precisam de tokens para tema).

#### Notas operacionais
- Validar `oklch()` no Safari 16.4+ antes de fechar.
- Manter fallback sRGB aproximado para browsers antigos (PostCSS ou manual).
- Cachear 2 stylesheets completos (dark/light) para troca atômica (não cascata profunda).

---

### Issue E — Web Awesome adoption (5 componentes)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `a11y:wcag-aa`, `breaking:visual`.

#### Resumo
Adotar **Web Awesome 3.9+** (MIT, Web Components, CDN, sucessor de Shoelace, dark/light nativo, ARIA built-in) e refatorar 5 componentes custom do OpenM para os equivalentes WA. Componentes: `<wa-dialog>` (substitui `Modal.open`), `<wa-tab>` (substitui tabs do Inspector atual), `<wa-tree>` (Transform Hub em árvore), `<wa-popover>` (tooltips custom), `<wa-dropdown>` (selects custom). Para `<wa-tree>` e `<wa-popover>` (imaturos), ter fallback HTML+CSS pronto.

#### Motivação
Web Components = zero acoplamento com vanilla JS, dark/light nativo, ARIA built-in economiza ~40% do trabalho de a11y. WA tem 50+ componentes via CDN, sem build step.

#### Solução proposta
- `openm/frontend/templates/index.html:14`: trocar Font Awesome por **Lucide** (1-2 KB inline SVG).
- `openm/frontend/templates/index.html:17-20`: adicionar `<script type="module" src="https://cdn.jsdelivr.net/npm/@awesome.me/awesome@3">`.
- `openm/frontend/static/js/icons.js` (63 linhas): reescrever para usar Lucide inline SVG.
- `openm/frontend/static/js/modals.js` (289 linhas): refatorar para usar `<wa-dialog>` como base; manter `Modal.confirm` e `Modal.conflictResolve` como wrappers.
- `openm/frontend/static/js/inspector.js` (226 linhas): refatorar tabs do inspector para usar `<wa-tab>`.
- `openm/frontend/static/js/transform_hub.js` (NOVO): árvore de transforms com `<wa-tree>` ou fallback HTML+CSS se WA tiver bugs de positioning.
- `openm/frontend/static/js/palette.js` (121 linhas): tooltips de cada entity type com `<wa-popover>` ou fallback.
- `openm/frontend/static/css/style.css`: remover estilos redundantes de Font Awesome; manter overrides de WA onde necessário.
- Smoke test: criar `tests/frontend/wa_smoke.html` (servido em dev) com os 5 componentes para validação.

#### Critérios de aceitação
- [ ] Web Awesome 3.9+ carregado via CDN
- [ ] 5 componentes WA adotados com fallbacks HTML+CSS prontos
- [ ] `Modal.open` agora usa `<wa-dialog>` por baixo
- [ ] Tabs do Inspector usam `<wa-tab>`
- [ ] Transform Hub usa `<wa-tree>` (ou fallback)
- [ ] Tooltips usam `<wa-popover>` (ou fallback)
- [ ] Selects custom usam `<wa-dropdown>`
- [ ] Lucide substitui Font Awesome em todos os templates
- [ ] Smoke test de WA em `tests/frontend/wa_smoke.html` (local only, não commitado em prod)
- [ ] Sem regressão nos fluxos existentes
- [ ] 100% compatibilidade com tema dark/light (via tokens da Issue D)

#### Esforço
4 (1 semana).

#### Dependências
**Issue D** (tokens para tema).

---

### Issue F — WCAG 2.2 AA foundations (focus, aria, keyboard nav)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `a11y:wcag-aa`.

#### Resumo
Implementar fundações de acessibilidade WCAG 2.2 AA: 4 skip links (Pular para canvas/sidebar/inspector/main), `:focus-visible` global em todos os botões/inputs, 2 `aria-live` regions (polite + assertive) com anúncios de screen reader para 13 eventos (seleção, transform start/complete/fail, save, conflict, 401, network, layout change, filter, LGPD banner), keyboard navigation completa em Cytoscape (Tab cicla nodes na ordem de ID, Enter move foco para inspector, Esc clear), touch targets ≥44×44px em todos os botões interativos.

#### Motivação
Zero acessibilidade atual (sem `aria-*`, sem `tabindex`, sem `:focus-visible` em botões, navegação por teclado limitada). WCAG 2.2 AA é padrão de mercado. Usuários com leitores de tela, baixa visão ou mobilidade reduzida estão 100% excluídos.

#### Solução proposta
- `openm/frontend/templates/index.html`: adicionar 4 skip links (`.skip-link` + `:focus` para mostrar).
- `openm/frontend/static/css/style.css`: regra global `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }` + utility `.sr-only` (1px absoluto, hidden visualmente, acessível a screen reader).
- `openm/frontend/static/css/style.css`: garantir `min-width/height: 44px` em todos os botões interativos (`.btn`, `.icon-btn`, `.cxtmenu-item`, `.inspector-tab`, etc.).
- `openm/frontend/templates/index.html`: adicionar 2 `<div aria-live="polite|assertive" id="sr-status|sr-alert" class="sr-only">` no `<body>`.
- `openm/frontend/static/js/app.js`: helper `App.announce(message, priority='polite')` que escreve na region apropriada.
- `openm/frontend/static/js/app.js`: 13 pontos de anúncio (selection, transform, save, conflict, etc.) — tabela em "Mapeamento de anúncios" do plano de design.
- `openm/frontend/static/js/graph.js`: adicionar `cy.elements().focusable: true` e escutar `keydown` no container do canvas para Tab/Shift+Tab/Enter/Espaço/Esc.
- `openm/frontend/static/js/app.js`: bindings dos atalhos já existentes (Ctrl+Z/Y/S/F) documentados em help overlay (Issue K).
- `docs/frontend-accessibility.md` (novo): guia de como adicionar novos componentes acessíveis.

#### Critérios de aceitação
- [ ] 4 skip links funcionais
- [ ] `:focus-visible` global visível em todos os botões
- [ ] 2 `aria-live` regions com anúncios para 13 eventos
- [ ] Keyboard nav completa em Cytoscape (Tab/Shift+Tab/Enter/Esc)
- [ ] Touch targets ≥44×44px em todos os botões
- [ ] Contraste de cor WCAG AA (todas as combinações de texto testadas com `prefers-contrast: more`)
- [ ] Page é navegável 100% por teclado (sem mouse)
- [ ] Documentação PT-BR em `docs/frontend-accessibility.md`
- [ ] Teste manual com screen reader (VoiceOver / NVDA / ChromeVox)

#### Esforço
3 (1 semana).

#### Dependências
**Issue D** (tokens) + **Issue E** (WA com ARIA built-in).

---

## Phase 3 — UX Overhaul (3 issues, ~2.5 semanas)

Release: `v1.1-frontend "OSINT"`.

---

### Issue G — Inspector 3-tabs + Timeline (Overview / Properties / Sightings)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `breaking:visual`.

#### Resumo
Refatorar `inspector.js` (226 linhas) para implementar 3 tabs (padrão OSINT Maltego/Kestrel/Linkurious): **Overview** (ícone + label + ID + source badge + resumo 1-linha + badges + 4 mini-actions), **Properties** (search/filter + lista agrupada por categoria + edição inline + "+ Add property"), **Sightings** (timeline cronológica reversa com filtros Todos/Transforms/Edições/Manual). Usa `<wa-tab>` da Issue E. Requer endpoint backend `GET /api/sightings?entity_id=X` — **confirmar antes de fechar**.

#### Motivação
Ponto focal do redesign. Detalhe em 3 tabs é convergência de 3 ferramentas líderes (Maltego, Kestrel, Linkurious). Timeline é especialmente crítico para entidades BR `ProcessoJudicial` (vai ter dezenas de `Movimentacao`).

#### Solução proposta
- `openm/frontend/static/js/inspector.js`: reescrever para 3 tabs.
- `openm/frontend/static/js/inspector.js`: novo método `Inspector.showSightings(entityId)` que chama `GET /api/sightings?entity_id=X` e renderiza timeline.
- `openm/frontend/templates/index.html:154-161` (inspector): nova estrutura HTML com 3 tabs WA.
- `openm/frontend/static/css/style.css`: styles para timeline (cards com ícone + data + descrição + source badge).
- **Backend (se necessário)**: novo endpoint `openm/api/sightings.py` que retorna lista de eventos por entity. **CRÍTICO**: confirmar com mantenedor backend se já existe ou precisa ser criado. Se não existir, esta issue vira bloqueadora.
- Testes E2E manual: criar `ProcessoJudicial`, rodar transform DataJud (quando existir), verificar timeline populada.

#### Critérios de aceitação
- [ ] 3 tabs funcionais (Overview / Properties / Sightings)
- [ ] Overview: ícone + label + ID + source badge + resumo + 4 mini-actions
- [ ] Properties: search/filter + lista agrupada + edição inline + "+ Add property"
- [ ] Sightings: timeline cronológica reversa com filtros
- [ ] Endpoint backend `/api/sightings` confirmado e funcionando (ou mock criado explicitamente)
- [ ] Compatibilidade com todas as 23 entidades (placeholder vazio para tipos sem sightings)
- [ ] Responsivo: 3 tabs viram accordion < 768px
- [ ] Documentação PT-BR em `docs/frontend-inspector.md`

#### Esforço
5 (1-2 semanas).

#### Dependências
**Issue E** (WA tabs) + **Issue D** (tokens). **Backend Sightings** — confirmar antes.

#### Risco
**Endpoint backend pode ser bloqueador** — confirmar com mantenedor backend antes de fechar a issue.

---

### Issue H — Transform Hub em árvore (sidebar tab 2)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `breaking:visual`.

#### Resumo
Adicionar 4ª tab na sidebar (depois de Entities/Investigations/Admin): **Transforms** com hub em árvore agrupado em 8 categorias (DNS, CEP, Identidade, CNPJ, Mercado, Sanções, Judicial, Macroeconomia) usando `<wa-tree>` (Issue E) ou fallback HTML+CSS. Cada nó da árvore mostra nome, ícone Lucide, e badge de status (free/registered/commercial). Click no transform abre painel central com descrição, inputs esperados, link para doc da fonte, exemplo de output, botão "Run on selection". Busca fuzzy com Fuse.js filtra em tempo real. Atalhos: `Cmd+3` switch para tab Transforms, `Cmd+R` run transform, `Cmd+Shift+R` re-run último.

#### Motivação
Padrão Maltego Transform Hub é referência do mercado. Sidebar atual com palette linear não escala para 6 atuais + 6 BR = 12 transforms. Agrupamento por categoria é navegabilidade pura.

#### Solução proposta
- `openm/frontend/templates/index.html:59-134` (sidebar): adicionar 4ª tab "Transforms" entre Investigations e Admin.
- `openm/frontend/static/js/transform_hub.js` (NOVO): ~250 linhas, classe `TransformHub` similar ao `Palette`.
- `openm/frontend/static/js/transform_hub.js`: usar `<wa-tree>` (Issue E) ou fallback HTML+CSS.
- `openm/frontend/static/js/transform_hub.js`: usar Fuse.js para busca fuzzy.
- `openm/frontend/static/js/transform_hub.js`: registrar 12 transforms (6 atuais + 6 BR da v1.0-brazil) com metadata de categoria, ícone, source tier, descrição, link.
- `openm/frontend/templates/index.html`: painel central mostra detalhe do transform selecionado.
- `openm/frontend/static/css/style.css`: styles para tree (indentação, ícones, hover, selected).

#### Critérios de aceitação
- [ ] 4ª tab "Transforms" funcional com `Cmd+3`
- [ ] Árvore com 8 categorias e 12 transforms registrados
- [ ] Busca fuzzy Fuse.js em tempo real
- [ ] Painel central com descrição, inputs, link, exemplo, botão Run
- [ ] Badge de source tier (free/registered/commercial) por transform
- [ ] Ícone Lucide por transform
- [ ] Compatibilidade com WA tree (com fallback HTML+CSS pronto)
- [ ] Atalhos `Cmd+R` (run) e `Cmd+Shift+R` (re-run último)
- [ ] Documentação PT-BR

#### Esforço
3 (1 semana).

#### Dependências
**Issue E** (WA tree) + **Issue F** (keyboard shortcuts).

---

### Issue I — Graph Search & Filter Panel (Fuse.js + checkboxes)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `breaking:visual`.

#### Resumo
Adicionar painel lateral colapsável à esquerda do canvas (ou popover sobre o canvas) com: (a) busca fuzzy **Fuse.js 7.x** por label/property de todos os nodes, com highlight dos matches; (b) checkboxes por entity type (23 tipos) com contador; (c) toggle "Show only selected neighborhood" (depth 1-3). Atalho `Cmd+F` foca no campo de busca.

#### Motivação
Grafos >50 nodes sem busca são cegos. Filtros laterais permitem "esconder tudo que não é Empresa" para focar em uma análise. Padrão consolidado de Cytoscape Desktop + Gephi + Linkurious.

#### Solução proposta
- `openm/frontend/static/js/search_filter.js` (NOVO): ~300 linhas, classe `SearchFilter`.
- `openm/frontend/static/js/search_filter.js`: usar Fuse.js para indexar nodes por `label` + `properties.*`.
- `openm/frontend/templates/index.html:137-151` (canvas-area): adicionar popover flutuante à esquerda do canvas (canto superior) com busca + filtros.
- `openm/frontend/static/js/search_filter.js`: highlight visual de matches com classe CSS `cy-node-match` (border 3px `--accent`).
- `openm/frontend/static/js/search_filter.js`: checkboxes por entity type com contador dinâmico (total/visíveis).
- `openm/frontend/static/js/search_filter.js`: toggle "neighborhood" filtra para depth 1-3 do node selecionado.
- `openm/frontend/static/css/style.css`: styles para popover, checkboxes, highlight.
- `openm/frontend/static/js/app.js`: binding `Cmd+F` para focar no campo de busca.

#### Critérios de aceitação
- [ ] Busca fuzzy Fuse.js em todos os nodes (label + properties)
- [ ] Highlight visual de matches no canvas
- [ ] Checkboxes por entity type (23 tipos) com contador
- [ ] Toggle "Show only selected neighborhood" (depth 1-3)
- [ ] Atalho `Cmd+F` foca no campo de busca
- [ ] Performance: <100ms para 500 nodes
- [ ] Estado do filtro persiste na investigation
- [ ] Documentação PT-BR

#### Esforço
3 (1 semana).

#### Dependências
**Issue D** (tokens) + **Issue F** (atalhos).

---

## Phase 4 — Polish & Power-User (3 issues, ~1.5 semanas)

Release: `v1.1.x-frontend "Mobile"`.

---

### Issue J — Responsividade básica (5 breakpoints + drawer mobile)

**Labels**: `area:frontend`, `enhancement`, `priority:high`, `breaking:visual`.

#### Resumo
Adicionar media queries nos 5 breakpoints (640/768/1024/1280/1536px) e reorganizar layout: mobile <640px single-col com sidebar/inspector virando drawer overlay; tablet 640-1024px sidebar colapsável (toggle com ícone); topbar vira hamburger <768px; LGPD banner vira modal fullscreen <640px. Canvas modes bar (V/H/N/E) vira bottom-fixed em <1024px.

#### Motivação
Zero responsividade atual — analista externo em campo não consegue usar o app em tablet/phone. Caso de uso real (OSINT em viagem) está bloqueado.

#### Solução proposta
- `openm/frontend/static/css/style.css`: 5 media queries (640/768/1024/1280/1536px).
- `openm/frontend/static/css/style.css`: <640px sidebar/inspector vira `position: fixed; transform: translateX(-100%); transition: var(--dur-base);` com overlay `oklch(0% 0 0 / 0.50)`.
- `openm/frontend/static/css/style.css`: <768px topbar vira hamburger (botão toggle à esquerda), zones View/Edit/Persistence colapsam em menu `⋯`.
- `openm/frontend/static/css/style.css`: <640px LGPD banner vira modal fullscreen (Issue L).
- `openm/frontend/static/css/style.css`: <1024px canvas modes bar vira bottom-fixed com 4 botões grandes.
- `openm/frontend/static/js/app.js`: helper `App.toggleSidebar()` e `App.toggleInspector()`.
- `openm/frontend/static/js/app.js`: hotkey `Cmd+B` toggle sidebar, `Cmd+I` toggle inspector.

#### Critérios de aceitação
- [ ] 5 media queries funcionais
- [ ] <640px: single-col + drawers com overlay
- [ ] <768px: topbar vira hamburger
- [ ] <1024px: canvas modes bar vira bottom-fixed
- [ ] LGPD banner responsivo (modal fullscreen em mobile)
- [ ] Atalhos `Cmd+B` e `Cmd+I` funcionam
- [ ] Teste em iPhone (Safari), Android (Chrome), iPad (Safari)
- [ ] Screenshot review em 3 tamanhos (375/768/1280px)
- [ ] Documentação PT-BR em `docs/frontend-responsive.md`

#### Esforço
3 (1 semana).

#### Dependências
**Issue D** (tokens) + **Issue F** (atalhos).

---

### Issue K — Command Palette (cmdk-wc, Cmd+K)

**Labels**: `area:frontend`, `enhancement`, `priority:medium`, `a11y:wcag-aa`.

#### Resumo
Adicionar **cmdk-wc 1.x** (MIT, Web Component) para command palette global ativada por `Cmd+K` (mac) / `Ctrl+K` (win/linux). Registrar 30+ comandos agrupados (Navigation, Entity, Transform, View, Edit, Help) com ícones Lucide, busca fuzzy, breadcrumb de navegação. Adicionar overlay de atalhos ativado por `?` (fullscreen com grid de atalhos agrupados por região).

#### Motivação
Padrão Linear/Vercel/Slack. Power users preferem teclado. Descoberta de features (atualmente invisível).

#### Solução proposta
- `openm/frontend/templates/index.html:17-20`: adicionar `<cmdk-palette>` do cmdk-wc.
- `openm/frontend/static/js/command_palette.js` (NOVO): ~300 linhas, registra 30+ comandos.
- `openm/frontend/static/js/command_palette.js`: usar Fuse.js para ranking fuzzy.
- `openm/frontend/static/js/app.js`: binding `Cmd+K` para abrir palette.
- `openm/frontend/static/js/app.js`: binding `?` para overlay de atalhos.
- `openm/frontend/static/css/style.css`: styles para palette (largura 600px, centralizado, max 60vh).
- `openm/frontend/templates/index.html`: atalho `?` adicionado ao menu Help.

#### Critérios de aceitação
- [ ] cmdk-wc carregado via CDN
- [ ] Palette ativada por `Cmd+K` / `Ctrl+K`
- [ ] 30+ comandos registrados em 6 grupos
- [ ] Busca fuzzy Fuse.js
- [ ] Ícone Lucide por comando
- [ ] Breadcrumb de navegação
- [ ] Overlay de atalhos ativado por `?`
- [ ] ARIA compliant (combobox pattern)
- [ ] Performance: <50ms para abrir, <100ms para busca
- [ ] Documentação PT-BR

#### Esforço
3 (2-3 dias).

#### Dependências
**Issue D** + **Issue F** (atalhos).

---

### Issue L — Onboarding tour + 4 templates de investigation (opcional, v1.2 se apertar)

**Labels**: `area:frontend`, `enhancement`, `priority:low`, `i18n:pt-br`.

#### Resumo
Adicionar tour guiado de 5 passos com spotlight cutout (overlay com `box-shadow: 0 0 0 9999px oklch(0% 0 0 / 0.60)`) usando `<wa-dialog>` da Issue E. Adicionar 4 templates de investigation (Person OSINT, Company Investigation, Network Recon, Market Analysis) + Blank, cada um pré-populando 1 node-raiz + 1 edge + transforms sugeridos. Modal "Nova investigation" mostra grid 2x2 com thumbnails SVG.

#### Motivação
Onboarding é barato (Web Awesome já tem `<wa-dialog>`) e tem alto retorno de retenção. Templates dão "ponto de partida" para usuários novos.

#### Solução proposta
- `openm/frontend/static/js/onboarding.js` (NOVO): ~200 linhas, gerencia 5 passos do tour.
- `openm/frontend/static/js/onboarding.js`: usa `<wa-dialog>` + spotlight cutout via `box-shadow`.
- `openm/frontend/static/js/templates.js` (NOVO): ~150 linhas, 4 templates + Blank.
- `openm/frontend/static/illustrations/`: 4 SVGs 120x80 (thumbnails dos templates) + 4 ilustrações empty/error.
- `openm/frontend/static/js/app.js`: trigger do tour em primeiro login (`localStorage.openm.tourCompleted` ausente).
- `openm/frontend/static/js/app.js`: botão "Replay tour" no menu Help.
- `openm/frontend/static/js/modals.js`: novo modal "Nova investigation" com grid de templates.

#### Critérios de aceitação
- [ ] Tour 5 passos funcional com spotlight cutout
- [ ] Trigger em primeiro login, dismissível
- [ ] Botão "Replay tour" no menu Help
- [ ] 4 templates + Blank com 1 node-raiz pré-populado
- [ ] Thumbnails SVG 120x80 para cada template
- [ ] Transform sugerido por template
- [ ] Modal "Nova investigation" com grid 2x2
- [ ] Mobile: tour vira fullscreen steps
- [ ] Documentação PT-BR

#### Esforço
3 (1 semana). **Se ultrapassar 1 semana, mover para v1.2**.

#### Dependências
**Issue E** (WA dialog) + **Issue J** (responsividade).

---

## Issues adiadas (v2+)

| # | Título | Razão do adiamento |
|---|---|---|
| M | ESLint + Prettier para o frontend | YAGNI sem build step; reativar quando entrar build step |
| N | Playwright E2E smoke tests | Excessivo para v1; vira v1.1 ou v2 quando houver mais features UI |
| O | Collaboration tempo real (WebSocket) | Requer redesign do backend; vira v2.0 |
| P | IA natural-language query (Linkurious-style) | Requer LLM integration; vira v2.0 |
| Q | Mapa geográfico (Leaflet) para `Endereco` | Ativo em v2, quando muitas entidades `Endereco` existirem |

---

## Decisões de modelagem (registradas)

Adotadas na Phase 1-4 e refletidas em todas as issues.

1. **Web Awesome 3.9+** como design system (MIT, Web Components, CDN, dark/light nativo, ARIA built-in). Web Components = zero acoplamento com vanilla JS.
2. **Cytoscape 3.31.1** mantido (atualizar de 3.26 é drop-in; NÃO migrar para Sigma.js/Reagraph/react-flow/G6).
3. **CSS custom properties em `oklch()`** com variantes dark/light via `[data-theme]`. CSS vars é o idioma certo para esta stack.
4. **Notyf 3.x** (3 KB) para toasts — maduro, ARIA built-in.
5. **Fuse.js 7.x** (~6 KB) para busca fuzzy — perfeito para nodes, transforms, investigations.
6. **hotkeys-js 4.0.3** (10 KB) para atalhos com scopes.
7. **cmdk-wc 1.x** (15 KB) para command palette (opcional, Phase 4).
8. **Lucide** (ISC, 1-2 KB inline) substitui Font Awesome 6.5.1 — alinhamento Maltego, melhor cobertura.
9. **Vanilla JS + `window.*`** mantido (NÃO refatorar para ES modules até entrar build step).
10. **Dark-first v1, light "beta" v1.1** — toggle existe mas default = dark, screenshots revisadas em v1.1.
11. **Templates pré-populam 1 node-raiz** (não só sugerem transforms).

---

## Roteiro de publicação

### Ordem de merge (sugestão)

| Semana | Issues | Marco |
|---|---|---|
| 1 | **A**, **B** | Quick wins visíveis (canvas + toasts) |
| 2 | **C** | Undo/Redo expandido (release `v1.0-frontend "Grafo+"`) |
| 3 | **D** (BLOQUEADOR) | Design System & Theming (início) |
| 4 | **E** | Web Awesome adoption (release `v1.0.1-frontend "Tema"`) |
| 5 | **F** | WCAG 2.2 AA foundations (release `v1.0.2-frontend "A11y"`) |
| 6 | **G** | Inspector 3-tabs (release `v1.1-frontend "OSINT"` parte 1) |
| 7 | **H**, **I** | Transform Hub + Search (release `v1.1-frontend "OSINT"`) |
| 8 | **J**, **K** | Responsividade + Command Palette (release `v1.1.x-frontend "Mobile"`) |
| 9 | **L** (opcional) | Onboarding tour (release `v1.2-frontend`) |

### Ações concretas para o mantenedor

1. **Criar milestone** `v1.0-frontend "Tema"` no GitHub (e subsequentes).
2. **Criar labels** novos (`a11y:wcag-aa`, `perf:critical`, `theme:dark`, `theme:light`, `breaking:visual`).
3. **Abrir as 11 issues** com labels e dependências. Usar template existente (não há template `frontend.yml` ainda; considerar criar um ou reusar `feature.yml`).
4. **Issue D primeiro** (BLOQUEADOR) — começar prototipagem de tokens oklch imediatamente.

---

## Métricas de sucesso

- 11 issues fechadas em 7.5 semanas (ritmo sustentável).
- 0 regressão em transforms existentes.
- WCAG 2.2 AA em 100% das páginas.
- Light mode funcional (mesmo como "beta" em v1).
- Page navegável 100% por teclado.
- Mobile (375px) e tablet (768px) usáveis.
- Performance: <100ms para re-style de tema em 500 nodes; <50ms para abrir command palette.

---

> **Última atualização**: gerado a partir de `~/dev/osint-projetc/.slim/deepwork/frontend-redesign.md` após discovery (explorer), research de libs (librarian), proposta visual (designer) e revisão estratégica (oracle).
