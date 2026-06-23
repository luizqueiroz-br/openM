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
