document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const expiresParam = urlParams.get('expires');
    const expiresAt = expiresParam ? parseInt(expiresParam, 10) : null;
    const hasError = urlParams.has('error');

    const loginBtn = document.getElementById('login-btn');
    const errorMsg = document.getElementById('error-msg');
    const loginForm = document.getElementById('login-form');

    if (!loginBtn || !errorMsg || !loginForm) return;

    if (expiresAt && !isNaN(expiresAt) && expiresAt > Date.now()) {
        loginBtn.disabled = true;
        loginBtn.classList.remove('hover:bg-emerald-500', 'bg-emerald-900');
        loginBtn.classList.add('bg-red-950/40', 'border', 'border-red-500/30', 'text-red-400', 'cursor-not-allowed');

        Array.from(loginForm.elements).forEach(element => {
            if (element.id !== 'login-btn') element.disabled = true;
        });

        errorMsg.classList.remove('hidden', 'text-red-400');
        errorMsg.classList.add('text-orange-400');
        errorMsg.innerText = "⚠️ TOO MANY FAILED ATTEMPTS";

        const updateClock = () => {
            const now = Date.now();
            const remainingSeconds = Math.max(0, Math.ceil((expiresAt - now) / 1000));
            loginBtn.innerHTML = `TERMINAL_LOCKED (<span id="countdown-clock">${remainingSeconds}</span>s)`;
            if (remainingSeconds <= 0) {
                clearInterval(ticker);
                window.location.replace('/frontend/internal_ops/login.html');
            }
        };

        updateClock();
        const ticker = setInterval(updateClock, 1000);
        return;
    }

    if (hasError) {
        errorMsg.classList.remove('hidden');
        errorMsg.classList.add('text-red-400');
        errorMsg.innerText = "Err: invalid_credentials";
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        loginBtn.disabled = true;
        loginBtn.classList.add('opacity-50', 'cursor-not-allowed');
        loginBtn.innerHTML = `<span class="animate-pulse">DECRYPTING...</span>`;

        const formData = new FormData(loginForm);
        const plainDataObject = Object.fromEntries(formData.entries());

        try {
            const response = await Security.authFetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(plainDataObject)
            });

            if (response.ok) {
                window.location.replace('/frontend/internal_ops/dashboard.html');
            }
            else if (response.status === 423 || response.status === 429) {
                const data = await response.json().catch(() => ({}));
                const cooldownSeconds = data.seconds || data.cooldown || 60;
                const targetTimestamp = Date.now() + (cooldownSeconds * 1000);
                window.location.replace(`/frontend/internal_ops/login.html?expires=${targetTimestamp}`);
            }
            else {
                window.location.replace('/frontend/internal_ops/login.html?error=true');
            }
        } catch (err) {
            console.error("🚨 SYSTEM_OFFLINE: Handshake aborted.");
            errorMsg.classList.remove('hidden');
            errorMsg.innerText = "Err: system_offline";

            loginBtn.disabled = false;
            loginBtn.innerHTML = "Retry Decryption";
            loginBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        }
    });
});