/**
 * Permissões do frontend (issue #3).
 *
 * Fonte da verdade: o backend (`@require_role` em `openm/api/*`).
 * Aqui só escondemos/disabilitamos a UI para o usuário não ver ações
 * que serão bloqueadas pelo servidor. **Toda checagem de segurança
 * real acontece no backend** — o frontend é apenas UX.
 *
 * Helpers:
 *   - can(role, action): true se o role pode executar a action
 *   - applyRoleGates(root): aplica data-roles em todos os elementos
 *     dentro de `root` (default: document). Elementos com
 *     `data-roles="admin,analyst"` ficam visíveis só para esses roles.
 */

(function () {
    'use strict';

    // ============ Helpers ============

    const ROLES = ['admin', 'analyst', 'viewer'];

    /**
     * Testa se o role do usuário tem permissão para uma action.
     *
     * Mantém alinhamento com a matriz de permissões do backend
     * (ver docs/rbac.md e tests/test_rbac.py).
     */
    function can(role, action) {
        if (!role) return false;
        switch (action) {
            // ============ Investigations ============
            case 'investigation:read':
                return ['admin', 'analyst', 'viewer'].includes(role);
            case 'investigation:create':
            case 'investigation:update':
            case 'investigation:archive':
            case 'investigation:unarchive':
                return ['admin', 'analyst'].includes(role);

            // ============ Entities ============
            case 'entity:create':
            case 'entity:update':
            case 'entity:delete':
                return ['admin', 'analyst'].includes(role);

            // ============ Edges ============
            case 'edge:create':
            case 'edge:delete':
                return ['admin', 'analyst'].includes(role);

            // ============ Transforms ============
            case 'transform:run':
                return ['admin', 'analyst'].includes(role);

            // ============ API Keys ============
            case 'key:read':
            case 'key:create':
            case 'key:delete':
                return ['admin', 'analyst'].includes(role);

            // ============ Admin (gerenciamento de usuários) ============
            case 'user:list':
            case 'user:set-role':
            case 'user:set-active':
                return role === 'admin';

            default:
                return false;
        }
    }

    /**
     * Aplica `data-roles` a todos os elementos com esse atributo.
     * Esconde elementos cujo role do usuário não está na lista.
     */
    function applyRoleGates(user, root) {
        const scope = root || document;
        if (!user || !user.role) return;
        const role = user.role;
        const elements = scope.querySelectorAll('[data-roles]');
        elements.forEach((el) => {
            const allowed = (el.getAttribute('data-roles') || '')
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean);
            const visible = allowed.length === 0 || allowed.includes(role);
            el.hidden = !visible;
            // Para botões, desabilitar é mais explícito que esconder.
            // Mas hide-by-default em data-roles é o esperado.
        });
    }

    /**
     * Retorna a action de um botão de acordo com data-action, ou null
     * se não houver. Útil para centralizar a checagem de permissão
     * antes de disparar handlers de UI.
     */
    function actionFromElement(el) {
        if (!el) return null;
        return el.getAttribute('data-action') || null;
    }

    window.OpenMPermissions = {
        can,
        applyRoleGates,
        actionFromElement,
        ROLES,
    };
})();
