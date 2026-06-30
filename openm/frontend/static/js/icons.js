/**
 * Mapeamento de tipos de entidade para ícones Font Awesome e cores.
 *
 * O campo `icon` (string FA-style) é mantido para compatibilidade com
 * graph.js (issue #127, Lane 2): ele faz mapeamento FA → glyph textual
 * (◉ ⌘ ✉ ☻ ₪ ▣) no canvas Cytoscape. NÃO REMOVER sem ajustar graph.js.
 *
 * O campo `lucide` é o nome Lucide correspondente (usado em DOM via
 * <i data-lucide="...">). Lane 3 vai trocar getIconHtml() para usar
 * `meta.lucide` em vez de `meta.icon` para ícones em DOM.
 */

const ENTITY_ICONS = {
    Domain: { icon: 'fa-globe', lucide: 'globe', color: '#38bdf8' },
    IPAddress: { icon: 'fa-network-wired', lucide: 'network', color: '#22c55e' },
    Email: { icon: 'fa-envelope', lucide: 'mail', color: '#f472b6' },
    Person: { icon: 'fa-user', lucide: 'user', color: '#a78bfa' },
    BankAccount: { icon: 'fa-credit-card', lucide: 'credit-card', color: '#fbbf24' },
    Device: { icon: 'fa-laptop', lucide: 'laptop', color: '#fb923c' },
    Generic: { icon: 'fa-circle', lucide: 'circle', color: '#64748b' },
};

const RELATION_ICONS = {
    RESOLVES_TO: 'arrow-right',
    OWNS: 'key',
    CONNECTED_TO: 'link',
    ASSOCIATED_WITH: 'link',
    SUSPICIOUS_LOGIN: 'triangle-alert',
    TRANSACTED_WITH: 'wallet',
    HOSTED_ON: 'server',
};

function getEntityMeta(type) {
    return ENTITY_ICONS[type] || ENTITY_ICONS.Generic;
}

function getIconHtml(type) {
    const meta = getEntityMeta(type);
    return `<i class="fa-solid ${meta.icon}" style="color:${meta.color}"></i>`;
}

function getIconBackground(type) {
    const meta = getEntityMeta(type);
    return meta.color;
}

/**
 * Retorna true se a entidade deve ser destacada como flagged por
 * VirusTotal (issue #6). Usado pelo graph.js para aplicar estilo
 * vermelho/laranja ao nó.
 *
 * Aceita tanto um objeto Entity quanto um dict `{data: {...}}` no
 * formato Cytoscape.js, ou ainda `{properties: {...}}`.
 */
function isFlagged(entity) {
    if (!entity) return false;
    const props = entity.properties
        || (entity.data && entity.data.properties)
        || (entity.data)
        || null;
    if (!props) return false;
    return props.virustotal_flagged === true
        || props.virustotal_flagged === "true";
}

/**
 * Cor de destaque quando a entidade está flagged (issue #6).
 */
function getFlaggedColor() {
    return '#ef4444';
}
