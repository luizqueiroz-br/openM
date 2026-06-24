/**
 * Admin UI (issue #42) — gerenciamento de usuários na sidebar esquerda.
 *
 * Requer role='admin' (a seção inteira é escondida via data-roles="admin"
 * + aplicada por OpenMPermissions.applyRoleGates no carregamento).
 *
 * Operações disponíveis:
 * - Listar todos os usuários via GET /api/admin/users
 * - Trocar role (admin/analyst/viewer) via PATCH /api/admin/users/<id>/role
 * - Ativar/desativar conta via PATCH /api/admin/users/<id>/active
 *
 * Confirmações via window.confirm() antes de ações destrutivas
 * (rebaixamento ou desativação de si mesmo).
 */

(function () {
    'use strict';

    const VALID_ROLES = ['admin', 'analyst', 'viewer'];

    // ============ Helpers ============

    /**
     * Mensagem de erro inline. Substitui conteúdo anterior.
     */
    function setError(message) {
        const el = document.getElementById('admin-error');
        if (!el) return;
        if (message) {
            el.textContent = message;
            el.hidden = false;
        } else {
            el.textContent = '';
            el.hidden = true;
        }
    }

    /**
     * Badge colorido para a coluna de role (mesmas cores da topbar).
     */
    function roleBadge(role) {
        const safeRole = VALID_ROLES.includes(role) ? role : 'viewer';
        return `<span class="role-badge" data-role="${safeRole}">${safeRole}</span>`;
    }

    /**
     * Formata timestamp ISO pra display local (curto).
     * Fallback gracioso se inválido.
     */
    function formatDate(iso) {
        if (!iso) return '—';
        try {
            const d = new Date(iso);
            return d.toLocaleDateString(undefined, {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
            });
        } catch {
            return iso;
        }
    }

    /**
     * Renderiza uma linha da tabela para um usuário.
     * `currentUserId` é usado para desabilitar controles no próprio user
     * (defesa em camadas — o backend também bloqueia, mas UX fica melhor).
     */
    function renderRow(user, currentUserId) {
        const isSelf = user.id === currentUserId;

        // Dropdown de role: mostra o role atual selecionado, desabilitado pra si mesmo.
        const roleOptions = VALID_ROLES.map((r) =>
            `<option value="${r}"${r === user.role ? ' selected' : ''}>${r}</option>`
        ).join('');

        return `
            <tr data-user-id="${user.id}">
                <td class="admin-col-email">${escapeHtml(user.email)}</td>
                <td class="admin-col-role">${roleBadge(user.role)}</td>
                <td class="admin-col-created">${formatDate(user.created_at)}</td>
                <td class="admin-col-actions">
                    <select class="admin-role-select"
                            data-action="change-role"
                            data-user-id="${user.id}"
                            ${isSelf ? 'disabled title="Você não pode alterar seu próprio role"' : ''}>
                        ${roleOptions}
                    </select>
                    <button class="btn small ${user.is_active ? 'danger' : 'primary'}"
                            data-action="toggle-active"
                            data-user-id="${user.id}"
                            ${isSelf ? 'disabled title="Você não pode desativar a si mesmo"' : ''}>
                        ${user.is_active ? 'Desativar' : 'Ativar'}
                    </button>
                </td>
            </tr>
        `;
    }

    /**
     * Escape básico pra evitar injeção de HTML em campos de texto.
     */
    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /**
     * Renderiza a tabela completa.
     */
    function renderTable(users, currentUserId) {
        const tbody = document.getElementById('admin-users-tbody');
        if (!tbody) return;
        if (!users || users.length === 0) {
            tbody.innerHTML = `
                <tr><td colspan="4" class="admin-empty">
                    Nenhum usuário cadastrado.
                </td></tr>`;
            return;
        }
        tbody.innerHTML = users.map((u) => renderRow(u, currentUserId)).join('');
    }

    /**
     * Lê o ID do user logado a partir de /api/auth/me (cacheado após 1ª leitura).
     */
    let _currentUserId = null;
    async function getCurrentUserId() {
        if (_currentUserId !== null) return _currentUserId;
        try {
            const data = await window.OpenMAPI.me();
            _currentUserId = data.user.id;
            return _currentUserId;
        } catch {
            return null;
        }
    }

    // ============ Operações ============

    /**
     * Carrega e renderiza a lista de usuários.
     */
    async function loadUsers() {
        setError(null);
        const refreshBtn = document.getElementById('admin-refresh');
        if (refreshBtn) refreshBtn.disabled = true;

        try {
            const currentUserId = await getCurrentUserId();
            const data = await window.OpenMAPI.listUsers();
            renderTable(data.users || [], currentUserId);
        } catch (err) {
            setError(`Erro ao listar usuários: ${err.message || err}`);
        } finally {
            if (refreshBtn) refreshBtn.disabled = false;
        }
    }

    /**
     * Troca o role de um usuário (com confirmação).
     */
    async function changeRole(userId, newRole, currentRole, email) {
        setError(null);

        // Defesa em camadas: confirma antes de chamar API.
        if (newRole === currentRole) return;
        if (!window.confirm(
            `Mudar o role de "${email}" de "${currentRole}" para "${newRole}"?`
        )) {
            // Reverter o select para o valor original.
            const select = document.querySelector(
                `select.admin-role-select[data-user-id="${userId}"]`
            );
            if (select) select.value = currentRole;
            return;
        }

        try {
            await window.OpenMAPI.setUserRole(userId, newRole);
            // Sucesso: recarrega a lista (atualiza o badge de role).
            await loadUsers();
        } catch (err) {
            setError(`Erro ao mudar role: ${err.message || err}`);
            // Reverter select.
            const select = document.querySelector(
                `select.admin-role-select[data-user-id="${userId}"]`
            );
            if (select) select.value = currentRole;
        }
    }

    /**
     * Ativa ou desativa um usuário (com confirmação).
     */
    async function toggleActive(userId, currentlyActive, email) {
        setError(null);
        const action = currentlyActive ? 'desativar' : 'ativar';
        if (!window.confirm(
            `${currentlyActive ? 'Desativar' : 'Ativar'} o usuário "${email}"?`
        )) {
            return;
        }

        try {
            await window.OpenMAPI.setUserActive(userId, !currentlyActive);
            await loadUsers();
        } catch (err) {
            setError(`Erro ao ${action} usuário: ${err.message || err}`);
        }
    }

    // ============ Bootstrap ============

    function bindEvents() {
        // Botão de atualizar.
        const refreshBtn = document.getElementById('admin-refresh');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadUsers);
        }

        // Delegação de eventos na tbody (change/click).
        const tbody = document.getElementById('admin-users-tbody');
        if (!tbody) return;

        tbody.addEventListener('change', async (event) => {
            const target = event.target;
            if (!target.matches('select[data-action="change-role"]')) return;
            const userId = parseInt(target.dataset.userId, 10);
            const newRole = target.value;
            const row = target.closest('tr');
            const email = row.querySelector('.admin-col-email').textContent;
            const currentRole = row.querySelector('.role-badge').dataset.role;
            await changeRole(userId, newRole, currentRole, email);
        });

        tbody.addEventListener('click', async (event) => {
            const btn = event.target.closest('button[data-action="toggle-active"]');
            if (!btn) return;
            const userId = parseInt(btn.dataset.userId, 10);
            const row = btn.closest('tr');
            const email = row.querySelector('.admin-col-email').textContent;
            const isCurrentlyActive = btn.classList.contains('danger');
            await toggleActive(userId, isCurrentlyActive, email);
        });
    }

    function init() {
        const section = document.getElementById('admin-section');
        if (!section) return;

        // Não inicializa handlers se a seção não for visível (não-admin).
        // Isso evita queries/listeners desnecessários.
        if (section.hidden) return;

        bindEvents();
        loadUsers();
    }

    // Inicializa quando o DOM estiver pronto.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expõe para testes ou re-init manual se necessário.
    window.OpenMAdmin = { loadUsers };
})();