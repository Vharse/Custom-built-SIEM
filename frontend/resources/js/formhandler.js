
const SecurityUtils = {
    getCookie: (name) => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    },

    notify: (message, theme = "emerald") => {
        const toast = document.createElement('div');
        const themeClasses = {
            emerald: 'border-emerald-500 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]',
            red: 'border-red-500 text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.2)]',
            yellow: 'border-yellow-500 text-yellow-400 shadow-[0_0_15px_rgba(234,179,8,0.2)]'
        };

        toast.className = `fixed bottom-8 right-8 px-6 py-3 border ${themeClasses[theme]} bg-[#0a0a0a] font-mono text-[10px] uppercase tracking-widest rounded-sm z-[100] animate-in fade-in slide-in-from-right-4 duration-300`;
        toast.innerText = `[LOG] > ${message}`;

        document.body.appendChild(toast);
        setTimeout(() => {
            toast.classList.add('animate-out', 'fade-out', 'slide-out-to-right-4');
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }
};

const SecurityScanner = (() => {
    const sanitize = (input) => {
        if (!input) return "";
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            "/": '&#x2F;',
        };
        const reg = /[&<>"'/]/ig;
        return input.replace(reg, (match) => (map[match]));
    };

    return {
        syncHandshake: async () => {
            try {
                const response = await fetch('/api/public/init-session', {
                    method: 'GET',
                    credentials: 'include',
                    mode: 'cors'
                });
                if (!response.ok) throw new Error("HANDSHAKE_REJECTED");

                const data = await response.json().catch(() => ({}));
                await new Promise(resolve => setTimeout(resolve, 150));
                
                return data.token || null;
            } catch (e) {
                console.error("Critical: Security Handshake Failed", e);
                throw new Error("NETWORK_UNREACHABLE");
            }
        },

        validate: (data) => {
            if (!data.name || data.name.trim().length < 2) return "NAME_TOO_SHORT";
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) return "INVALID_EMAIL";
            if (!data.message || data.message.trim().length < 10) return "MESSAGE_TOO_SHORT";
            return null;
        },

        clean: (data) => ({
            name: sanitize(data.name.trim()),
            email: data.email.trim().toLowerCase(),
            message: sanitize(data.message.trim())
        })
    };
})();

document.addEventListener('DOMContentLoaded', () => {
    const auditForm = document.getElementById('auditForm');

    if (auditForm) {
        console.log("Vault Kernel: Form Interceptor Active");

        auditForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            e.stopPropagation();

            const btn = document.getElementById('submitBtn');

            const rawData = {
                name: document.getElementById('userName')?.value,
                email: document.getElementById('userEmail')?.value,
                message: document.getElementById('userMessage')?.value
            };

            const validationError = SecurityScanner.validate(rawData);
            if (validationError) {
                SecurityUtils.notify(`SEC_ALERT: ${validationError}`, "yellow");
                return;
            }

            if (btn) {
                btn.disabled = true;
                btn.innerHTML = `<span class="animate-pulse">ENCRYPTING...</span>`;
            }

            try {
                const fallbackToken = await SecurityScanner.syncHandshake();
                let csrfToken = SecurityUtils.getCookie('csrf_token') || fallbackToken;

                const cleanedData = SecurityScanner.clean(rawData);

                const response = await fetch('/api/public/submit-inquiry', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken || '',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(cleanedData),
                    credentials: 'include',
                    mode: 'cors'
                });

                let result = {};
                try {
                    result = await response.json();
                } catch (jsonErr) {
                    console.warn(">> Response payload format exception or empty JSON matrix parsing handle.");
                }

                if (response.status !== 200 && response.status !== 201) {
                    const errorMsg = result && (result.detail || result.message) ? (result.detail || result.message) : "VAULT_REJECTION";
                    throw new Error(errorMsg);
                }

                console.log(">> Data safely ingested by FastAPI. Holding UI state for confirmation modal.");

                try {
                    auditForm.reset();
                    console.log(">> Ingestion successful. Flushing input forms.");
                } catch (resetErr) {
                    console.warn("Input reset context intercepted a layout drop bounce:", resetErr);
                }

                if (btn) {
                    btn.disabled = true;
                    btn.innerText = "DATA_VAULTED";
                }

                if (typeof Swal === 'undefined') {
                    console.error("CRITICAL: SweetAlert2 framework loading failure detected inside runtime instance context.");
                    alert(">> TRANSMISSION_VERIFIED\nYour communication payload has been filtered, sanitized, and safely committed to the security vault.");
                    window.location.reload();
                    return;
                }

                await Swal.fire({
                    title: '<span style="font-family: \'JetBrains Mono\', monospace; color: #10b981; font-size: 16px; font-weight: bold; tracking-wide;">>> TRANSMISSION_VERIFIED</span>',
                    html: '<p style="font-family: \'Space Grotesk\', sans-serif; color: #9ca3af; font-size: 13px;">Your communication payload has been filtered, sanitized, and safely committed to the security vault.</p>',
                    background: '#0a0a0a',
                    icon: 'success',
                    iconColor: '#10b981',
                    confirmButtonText: 'CLOSE_TERMINAL',
                    confirmButtonColor: '#065f46',

                    allowOutsideClick: false,
                    allowEscapeKey: false,

                    customClass: {
                        popup: 'border border-emerald-500/30 rounded-sm shadow-[0_0_30px_rgba(16,185,129,0.1)]',
                        confirmButton: 'font-mono text-[10px] tracking-widest uppercase px-6 py-3 rounded-xs cursor-pointer'
                    },
                    buttonsStyling: true
                });

                console.log(">> Operator confirmed CLOSE_TERMINAL action. Forcing viewport refresh.");
                window.location.reload();

            } catch (error) {
                console.error("Submission Failure Encountered:", error);
                SecurityUtils.notify(`CRIT_FAIL: ${error.message}`, "red");

                if (btn) {
                    btn.disabled = false;
                    btn.innerText = "Send Secure Transmission";
                }
            }
        });
    }
});