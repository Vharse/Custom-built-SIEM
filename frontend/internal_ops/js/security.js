(function () {
    if (window.Security) return;

    const BASE_URL = "/api";
    const LOGIN_ROUTE = "/frontend/internal_ops/login.html";

    const Security = {
        sanitizeText: (inputString) => {
            if (!inputString) return "";
            const tempContainer = document.createElement('div');
            tempContainer.textContent = inputString;
            return tempContainer.innerHTML;
        },

        getCSRFToken: () => {
            const matches = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
            return matches ? decodeURIComponent(matches[1]) : "";
        },

        authFetch: async (endpoint, options = {}) => {
            const finalUrl = endpoint.startsWith(BASE_URL) ? endpoint : `${BASE_URL}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`;

            const response = await fetch(finalUrl, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': Security.getCSRFToken(),
                    ...options.headers
                },
                credentials: 'include'
            });

            if (response.status === 401) {
                console.warn("🚨 SECURITY_GATE: 401 Unauthorized detected. Purging client state.");
                await Security.logout();
            }

            return response;
        },

        logout: async () => {
            try {
                await fetch(`${BASE_URL}/auth/logout`, { method: 'POST', credentials: 'include' });
            } catch (e) {
                // Fail-safe silent catch
            }
            window.location.replace(LOGIN_ROUTE);
        },

        enforceRoutingGate: async () => {
            const currentPath = window.location.pathname;

            if (currentPath.endsWith('/login.html') || currentPath === '/' || currentPath === LOGIN_ROUTE) {
                return;
            }

            try {
                const res = await Security.authFetch('/config/current-posture');
                if (!res.ok) {
                    window.location.replace(LOGIN_ROUTE);
                }
            } catch (err) {
                window.location.replace(LOGIN_ROUTE);
            }
        }
    };

    window.Object.freeze(Security);
    window.Security = Security;

    window.addEventListener('DOMContentLoaded', () => Security.enforceRoutingGate());
})();