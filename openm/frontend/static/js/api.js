/**
 * API client para o backend OpenM.
 */

const API_BASE = '/api';

async function api(path, options = {}) {
    const url = `${API_BASE}${path}`;
    const response = await fetch(url, {
        headers: { 'Content-Type': 'application/json' },
        ...options,
    });

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
        throw new Error(data.error || `HTTP ${response.status}`);
    }
    return data;
}

const OpenMAPI = {
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

    createEdge: ({ from_id, to_id, rel_type, properties = {} }) =>
        api('/edge', {
            method: 'POST',
            body: JSON.stringify({ from_id, to_id, rel_type, properties }),
        }),

    deleteEdge: (id) =>
        api(`/edge/${encodeURIComponent(id)}`, { method: 'DELETE' }),

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

    getSubgraph: (entityId, depth = 2) =>
        api(`/subgraph/${encodeURIComponent(entityId)}?depth=${depth}`),

    createInvestigation: (title, description, rootEntityId) =>
        api('/investigations', {
            method: 'POST',
            body: JSON.stringify({ title, description, root_entity_id: rootEntityId }),
        }),

    listInvestigations: () => api('/investigations'),

    listKeys: () => api('/keys'),

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
};
