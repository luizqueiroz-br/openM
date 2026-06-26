/**
 * API client para o backend OpenM.
 *
 * Usa cookies httpOnly para auth (setados em /api/auth/login).
 * Inclui interceptador que detecta 401 e tenta refresh automático;
 * se falhar, redireciona pra /login.
 */

const API_BASE = '/api';
const AUTH_ENDPOINTS = {
    refresh: `${API_BASE}/auth/refresh`,
    login: `${API_BASE}/auth/login`,
    register: `${API_BASE}/auth/register`,
    logout: `${API_BASE}/auth/logout`,
    me: `${API_BASE}/auth/me`,
};

// Flag pra evitar loop infinito de refresh quando o próprio refresh falha.
let _refreshing = null;

async function api(path, options = {}) {
    const url = `${API_BASE}${path}`;
    const response = await fetch(url, {
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        ...options,
    });

    // 401: tenta refresh uma vez e repete a request original.
    if (response.status === 401 && !options._retried) {
        const refreshed = await tryRefresh();
        if (refreshed) {
            return api(path, { ...options, _retried: true });
        }
        // Refresh falhou: manda pro login.
        redirectToLogin();
        throw new Error('sessão expirada');
    }

    let data = {};
    const text = await response.text();
    if (text) {
        try {
            data = JSON.parse(text);
        } catch (e) {
            data = { error: text };
        }
    }

    if (!response.ok) {
        // Preserva status code + body no Error para que catch sites
        // possam reagir (ex.: AutoSave detecta 404 e para o loop).
        // Retrocompat: `err.message` continua funcionando como antes.
        const message = data.error || `HTTP ${response.status}`;
        const err = new Error(message);
        err.status = response.status;
        err.body = data;
        throw err;
    }
    return data;
}

async function tryRefresh() {
    // Coalesce múltiplas chamadas paralelas num único refresh.
    if (_refreshing) return _refreshing;

    _refreshing = (async () => {
        try {
            const resp = await fetch(AUTH_ENDPOINTS.refresh, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: '{}', // refresh usa o cookie httpOnly, body pode ser vazio
            });
            return resp.ok;
        } catch {
            return false;
        } finally {
            // Libera depois de um tick pra não coalescer a próxima chamada.
            setTimeout(() => { _refreshing = null; }, 0);
        }
    })();

    return _refreshing;
}

function redirectToLogin() {
    if (window.location.pathname !== '/login') {
        window.location.href = '/login';
    }
}

const OpenMAPI = {
    // ============ Auth ============
    me: () => api('/auth/me'),

    login: (email, password) =>
        api('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        }),

    register: (email, password) =>
        api('/auth/register', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        }),

    logout: () =>
        api('/auth/logout', {
            method: 'POST',
            body: '{}',
        }),

    // ============ Entities ============
    createEntity: (type, value, properties = {}) =>
        api('/entity', {
            method: 'POST',
            body: JSON.stringify({ type, value, ...properties }),
        }),

    updateEntity: (id, properties) =>
        api(`/entity/${encodeURIComponent(id)}`, {
            method: 'PATCH',
            body: JSON.stringify({ properties }),
        }),

    deleteEntity: (id) =>
        api(`/entity/${encodeURIComponent(id)}`, { method: 'DELETE' }),

    // ============ Edges ============
    createEdge: ({ from_id, to_id, rel_type, properties = {} }) =>
        api('/edge', {
            method: 'POST',
            body: JSON.stringify({ from_id, to_id, rel_type, properties }),
        }),

    deleteEdge: (id) =>
        api(`/edge/${encodeURIComponent(id)}`, { method: 'DELETE' }),

    // ============ Transforms ============
    listTransforms: (entityType) =>
        api(`/transforms/${encodeURIComponent(entityType)}`),

    runTransform: (entityId, transformName, entityType, value, properties = {}) =>
        api('/run_transform', {
            method: 'POST',
            body: JSON.stringify({
                entity_id: entityId,
                transform_name: transformName,
                entity_type: entityType,
                value,
                properties,
            }),
        }),

    // ============ Graph ============
    getSubgraph: (entityId, depth = 2) =>
        api(`/subgraph/${encodeURIComponent(entityId)}?depth=${depth}`),

    // ============ Investigations (v2 — issues #26, #27, #28) ============
    createInvestigation: (title, description, rootEntityId) =>
        api('/investigations', {
            method: 'POST',
            body: JSON.stringify({ title, description, root_entity_id: rootEntityId }),
        }),

    listInvestigations: (params = {}) => {
        // params: { status, search, sort }
        const qs = new URLSearchParams();
        if (params.status) qs.set('status', params.status);
        if (params.search) qs.set('search', params.search);
        if (params.sort) qs.set('sort', params.sort);
        const suffix = qs.toString() ? `?${qs.toString()}` : '';
        return api(`/investigations${suffix}`);
    },

    getInvestigation: (id) => api(`/investigations/${id}`),

    updateInvestigation: (id, changes, { ifMatch } = {}) =>
        api(`/investigations/${id}`, {
            method: 'PUT',
            body: JSON.stringify(changes),
            headers: ifMatch !== undefined && ifMatch !== null
                ? { 'If-Match': `"${ifMatch}"` }
                : undefined,
        }),

    archiveInvestigation: (id) =>
        api(`/investigations/${id}/archive`, { method: 'POST' }),

    unarchiveInvestigation: (id) =>
        api(`/investigations/${id}/unarchive`, { method: 'POST' }),

    // Hard delete (issue #35): 204 No Content. ApiError tem .status=204.
    deleteInvestigation: (id) =>
        api(`/investigations/${id}`, { method: 'DELETE' }),

    // ============ API Keys ============
    listKeys: () => api('/keys'),

    // Lista os services disponiveis para cadastro de chave.
    // Popula o <select id="key-service"> no painel de API Keys.
    listKeyServices: () => api('/transforms/services'),

    saveKey: (serviceName, keyValue, keyType) =>
        api('/keys', {
            method: 'POST',
            body: JSON.stringify({
                service_name: serviceName,
                key_value: keyValue,
                key_type: keyType,
            }),
        }),

    deleteKey: (id) => api(`/keys/${id}`, { method: 'DELETE' }),

    // ============ Admin (issue #3, #42) ============
    // Endpoints exclusivos de role='admin'. A UI esconde os elementos
    // via data-roles, mas o backend revalida — nunca confie só na UI.
    listUsers: () => api('/admin/users'),

    setUserRole: (userId, role) =>
        api(`/admin/users/${userId}/role`, {
            method: 'PATCH',
            body: JSON.stringify({ role }),
        }),

    setUserActive: (userId, isActive) =>
        api(`/admin/users/${userId}/active`, {
            method: 'PATCH',
            body: JSON.stringify({ is_active: isActive }),
        }),
};

// ============ Auth bootstrap ============

const OpenMAuth = {
    async bootstrap() {
        try {
            const data = await OpenMAPI.me();
            return data.user;
        } catch {
            redirectToLogin();
            return null;
        }
    },

    async logout() {
        try {
            await OpenMAPI.logout();
        } finally {
            window.location.href = '/login';
        }
    },
};

window.OpenMAPI = OpenMAPI;
window.OpenMAuth = OpenMAuth;