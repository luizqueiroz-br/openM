/**
 * Mapeamento de tipos de entidade para ícones Font Awesome e cores.
 */

const ENTITY_ICONS = {
    Domain: { icon: 'fa-globe', color: '#38bdf8' },
    IPAddress: { icon: 'fa-network-wired', color: '#22c55e' },
    Email: { icon: 'fa-envelope', color: '#f472b6' },
    Person: { icon: 'fa-user', color: '#a78bfa' },
    BankAccount: { icon: 'fa-credit-card', color: '#fbbf24' },
    Device: { icon: 'fa-laptop', color: '#fb923c' },
    Generic: { icon: 'fa-circle', color: '#64748b' },
};

const RELATION_ICONS = {
    RESOLVES_TO: 'fa-arrow-right',
    OWNS: 'fa-key',
    CONNECTED_TO: 'fa-link',
    ASSOCIATED_WITH: 'fa-link',
    SUSPICIOUS_LOGIN: 'fa-triangle-exclamation',
    TRANSACTED_WITH: 'fa-money-bill-transfer',
    HOSTED_ON: 'fa-server',
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
