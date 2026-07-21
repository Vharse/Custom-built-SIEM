document.addEventListener('DOMContentLoaded', async () => {
    const target = document.getElementById('admin_sidebar-target');
    if (!target) return;

    const sidebarPath = 'components/admin_sidebar.html';
    console.log("Attempting to load sidebar from:", new URL(sidebarPath, window.location.href).href);

    try {
        const response = await fetch(sidebarPath);
        if (!response.ok) throw new Error(`Status: ${response.status}`);

        const html = await response.text();
        target.innerHTML = html;

        const logoutBtn = target.querySelector('button');
        if (logoutBtn) {
            logoutBtn.onclick = (e) => {
                e.preventDefault();
                console.log("🔒 LOGIX_AUTH: Handing over to master session termination sequence...");
                if (window.Security && typeof window.Security.logout === 'function') {
                    window.Security.logout();
                } else {
                    console.error("🚨 UI_KERNEL: Core Security object missing during logout execution.");
                    window.location.replace('vault.html');
                }
            };
        }

        const currentPage = window.location.pathname.split("/").pop() || 'index.html';
        const links = target.querySelectorAll('a');

        links.forEach(link => {
            const href = link.getAttribute('href');
            if (href === currentPage || (currentPage === 'dashboard.html' && href.includes('dashboard'))) {
                link.classList.add('bg-emerald-500/10', 'text-emerald-500', 'border-r-2', 'border-emerald-500');
                link.classList.remove('text-gray-500');
            }
        });

        console.log("🔒 UI_KERNEL: Sidebar injected successfully.");

        if (target.querySelector('#sidebar-inbox-link')) {
            AlertStateManager.init();
        }

    } catch (err) {
        console.warn("🛡️ UI_KERNEL: Sidebar failed to load, but maintaining session.", err);
        target.innerHTML = `<div class="p-4 text-red-500 text-[10px] mono">SIDEBAR_LOAD_ERROR</div>`;
    }
});


const AlertStateManager = {
    linkElement: null,

    init: function () {
        this.linkElement = document.getElementById('sidebar-inbox-link');
        if (!this.linkElement) return;

        this.evaluateOutstandingAlerts();

        setInterval(() => this.evaluateOutstandingAlerts(), 30000);

        window.AlertStateManager = this;
    },

    evaluateOutstandingAlerts: async function () {
        try {
            const response = await fetch('/api/manage/security-inbox'); // Adjusted route to match your API structure
            if (!response.ok) return;

            const data = await response.json();

            if (data.alerts && data.alerts.length > 0) {
                this.triggerBlink();
            } else {
                this.suppressBlink();
            }
        } catch (err) {
            console.error("🚨 UI_KERNEL: Failed to sync security-inbox matrix layout:", err);
        }
    },

    triggerBlink: function () {
        if (this.linkElement) {
            this.linkElement.classList.add('animate-pulse', 'bg-red-500/20', 'border-red-500/40', 'text-red-400');
        }
    },

    suppressBlink: function () {
        if (this.linkElement) {
            this.linkElement.classList.remove('animate-pulse', 'bg-red-500/20', 'border-red-500/40', 'text-red-400');
        }
    }
};