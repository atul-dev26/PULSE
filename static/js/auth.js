/**
 * PULSE shared authentication utilities.
 * Token is stored in sessionStorage and cleared when the browser closes.
 */
(function (global) {
    'use strict';

    const TOKEN_KEY = 'pulse_auth_token';
    const LOGIN_PATH = '/login';
    let authReadyPromise = null;

    function getToken() {
        return sessionStorage.getItem(TOKEN_KEY);
    }

    function setToken(token) {
        sessionStorage.setItem(TOKEN_KEY, token);
    }

    function clearToken() {
        sessionStorage.removeItem(TOKEN_KEY);
    }

    function isLoginPage() {
        return global.location.pathname === LOGIN_PATH;
    }

    function authHeaders(extraHeaders) {
        const headers = Object.assign({}, extraHeaders || {});
        const token = getToken();
        if (token) {
            headers['Authorization'] = 'Bearer ' + token;
        }
        return headers;
    }

    /**
     * fetch() wrapper that attaches JWT and redirects to /login on 401.
     */
    async function authFetch(url, options) {
        const opts = Object.assign({}, options || {});
        const existing = opts.headers;

        if (existing instanceof Headers) {
            const merged = authHeaders(Object.fromEntries(existing.entries()));
            opts.headers = merged;
        } else {
            opts.headers = authHeaders(existing || {});
        }

        const response = await fetch(url, opts);

        if (response.status === 401 && !isLoginPage()) {
            clearToken();
            global.location.href = LOGIN_PATH;
        }

        return response;
    }

    function logout() {
        clearToken();
        authReadyPromise = null;
        global.location.href = LOGIN_PATH;
    }

    function formatUsername(username) {
        if (!username) return 'User';
        return username.charAt(0).toUpperCase() + username.slice(1);
    }

    function updateUserHeader(user) {
        const nameEl = document.getElementById('headerUserName');
        if (nameEl && user && user.username) {
            nameEl.textContent = formatUsername(user.username);
        }
    }

    /**
     * Verify token exists and is valid; redirect to /login if not.
     * Returns user object on success, null on failure.
     */
    async function requireAuth() {
        if (isLoginPage()) {
            return null;
        }

        if (authReadyPromise) {
            return authReadyPromise;
        }

        authReadyPromise = (async function () {
            const token = getToken();
            if (!token) {
                global.location.href = LOGIN_PATH;
                return null;
            }

            try {
                const response = await fetch('/api/v1/auth/me', {
                    headers: { 'Authorization': 'Bearer ' + token },
                });

                if (!response.ok) {
                    clearToken();
                    global.location.href = LOGIN_PATH;
                    return null;
                }

                const user = await response.json();
                updateUserHeader(user);
                return user;
            } catch (err) {
                clearToken();
                global.location.href = LOGIN_PATH;
                return null;
            }
        })();

        return authReadyPromise;
    }

    /**
     * Call on protected pages after DOM is ready.
     */
    async function guardPage() {
        if (document.body && document.body.dataset.authRequired === 'true') {
            await requireAuth();
        }
    }

    async function login(username, password) {
        const response = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password }),
        });
        return response;
    }

    global.PulseAuth = {
        getToken: getToken,
        setToken: setToken,
        clearToken: clearToken,
        authHeaders: authHeaders,
        fetch: authFetch,
        logout: logout,
        requireAuth: requireAuth,
        guardPage: guardPage,
        login: login,
        updateUserHeader: updateUserHeader,
        formatUsername: formatUsername,
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', guardPage);
    } else {
        guardPage();
    }
})(window);
