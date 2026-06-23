/**
 * Handlers dos formulários de login e registro.
 *
 * Ambos fazem POST JSON contra /api/auth/* e, em sucesso, deixam o
 * cookie httpOnly ser setado pelo backend — depois redireciona pra /.
 *
 * Em erro, exibe a mensagem genérica retornada pelo backend no elemento
 * .auth-error correspondente (sem revelar se o email existe, etc.).
 */

(function () {
    "use strict";

    const API_BASE = "/api/auth";

    function showError(el, message) {
        if (!el) return;
        el.textContent = message;
        el.hidden = false;
    }

    function hideError(el) {
        if (!el) return;
        el.textContent = "";
        el.hidden = true;
    }

    async function postJSON(url, body) {
        const resp = await fetch(url, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            // Mensagem genérica (anti-enumeração) ou específica do register.
            const msg = data.error || `HTTP ${resp.status}`;
            throw new Error(typeof msg === "string" ? msg : "Falha na requisição");
        }
        return data;
    }

    // ============ Login ============

    const loginForm = document.getElementById("login-form");
    if (loginForm) {
        const errorEl = document.getElementById("login-error");
        const submitBtn = loginForm.querySelector('button[type="submit"]');

        loginForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            hideError(errorEl);

            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value;

            submitBtn.disabled = true;
            const originalHtml = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Entrando...';

            try {
                await postJSON(`${API_BASE}/login`, { email, password });
                // Cookie httpOnly setado pelo backend; vai direto pra home.
                window.location.href = "/";
            } catch (err) {
                showError(errorEl, err.message || "Falha ao entrar");
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalHtml;
            }
        });
    }

    // ============ Register ============

    const registerForm = document.getElementById("register-form");
    if (registerForm) {
        const errorEl = document.getElementById("register-error");
        const submitBtn = registerForm.querySelector('button[type="submit"]');

        registerForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            hideError(errorEl);

            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value;
            const password2 = document.getElementById("password2").value;

            if (password !== password2) {
                showError(errorEl, "As senhas não conferem");
                return;
            }

            submitBtn.disabled = true;
            const originalHtml = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Criando...';

            try {
                await postJSON(`${API_BASE}/register`, { email, password });
                // Após registrar, autentica direto (sem precisar ir pro login).
                await postJSON(`${API_BASE}/login`, { email, password });
                window.location.href = "/";
            } catch (err) {
                showError(errorEl, err.message || "Falha ao registrar");
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalHtml;
            }
        });
    }
})();