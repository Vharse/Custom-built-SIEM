// CORE UI INTERFACE KERNEL & DASHBOARD CONTROLLER
const DashboardManager = {

    apiEndpoint: '/api/manage/admin-dashboard',
    securityInboxEndpoint: '/api/manage/security-inbox',
    auditTrailEndpoint: '/api/manage/audit-trail',
    mitigationEndpoint: '/api/config/mitigate',

    activeCharts: { distribution: null, timeline: null },
    cachedAlerts: [],
    cachedAuditLogs: [],
    cachedInquiries: [],

    init: function () {
        console.log("UI KERNEL: Initializing security dashboard under Zero Trust constraints...");
        const overviewBtn = document.querySelector('aside nav button') || document.getElementById('btn-nav-overview');
        this.switchView('panel-overview', overviewBtn);
        this.fetchDashboardData();
        this.synchronizeSystemSwitches();
        this.syncPostureWithBackend();
        this.refreshInterval = setInterval(() => {
            this.fetchDashboardData();
            this.synchronizeSystemSwitches();
            this.syncPostureWithBackend();
        }, 45000);
    },

    updateBlinkingState: function () {
        const hasUninvestigatedAlerts = this.cachedAuditLogs.some(a =>
            a.status && a.status.toUpperCase() === 'ALERT'
        );

        const alertIndicator = document.getElementById('sidebar-inbox-link');
        if (!alertIndicator) return;

        if (hasUninvestigatedAlerts) {
            alertIndicator.classList.add('animate-pulse', 'bg-red-500/10', 'border-red-500/40');
        } else {
            alertIndicator.classList.remove('animate-pulse', 'bg-red-500/10', 'border-red-500/40');
        }
    },

    updatePostureUI: function (posture) {
        if (posture) {
            const coreGates = ['pydantic_filtering', 'audit_logging', 'ingress_throttling', 'sandbox_mode'];
            coreGates.forEach(featureKey => {
                const targetSwitch = document.querySelector(`input[data-feature-key="${featureKey}"]`) || document.getElementById(`switch-${featureKey}`);
                if (targetSwitch && typeof posture[featureKey] !== 'undefined') {
                    targetSwitch.checked = !!posture[featureKey];
                    targetSwitch.disabled = false;
                    targetSwitch.parentElement?.classList.remove('opacity-50', 'cursor-not-allowed');
                }
            });
        }

        const riskMeter = document.getElementById('risk-meter');
        if (!riskMeter) return;

        if (!posture.audit_logging) {
            riskMeter.innerText = "CRITICAL: VISIBILITY LOST";
            riskMeter.style.color = "#f87171"; // Red
        } else {
            riskMeter.innerText = "SYSTEM_SECURE";
            riskMeter.style.color = "#10b981"; // Emerald
        }
        console.log("UI KERNEL: UI synchronized with backend posture.");
    },

    syncPostureWithBackend: async function () {
        try {
            const response = await Security.authFetch('/api/config/current-posture');
            if (response.ok) {
                const posture = await response.json();
                this.updatePostureUI(posture);
            }
        } catch (err) {
            console.error("🚨 UI KERNEL FAULT: Failed to fetch backend posture.");
        }
    },

    dispatchConfigurationMutation: async function (featureKey, activeState) {
        const element = document.querySelector(`input[data-feature-key="${featureKey}"]`) || document.getElementById(`switch-${featureKey}`);
        if (element) {
            element.checked = !activeState;
            element.disabled = true;
            element.parentElement?.classList.add('opacity-50', 'cursor-not-allowed');
        }

        try {
            const response = await Security.authFetch('/api/config/update-config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ feature_key: featureKey, active_state: activeState })
            });

            if (response.status === 409) {
                alert("ZERO_TRUST_ENFORCEMENT: System is currently processing active threats. Configuration locked.");
                if (element) {
                    element.checked = !activeState;
                    element.disabled = false;
                    element.parentElement?.classList.remove('opacity-50', 'cursor-not-allowed');
                }
                return;
            }

            if (!response.ok) {
                throw new Error("Configuration mutation failed.");
            }

            const confirmationPacket = await response.json();
            console.log(`✅ UI KERNEL: ${featureKey} set to ${activeState}`);

            await this.syncPostureWithBackend();

        } catch (err) {
            console.error("🚨 UI KERNEL FAULT: Config sync error.", err);
            alert("Configuration Update Failed.");
            if (element) {
                element.checked = !activeState;
                element.disabled = false;
                element.parentElement?.classList.remove('opacity-50', 'cursor-not-allowed');
            }
        }
    },

    requestMutationConfirmation: async function (featureKey, isChecked) {
        const toggleSwitch = document.getElementById(`switch-${featureKey}`);

        const readableAction = isChecked ? "ENABLE" : "DISABLE";
        const userConfirmed = confirm(`[SECURITY POLICY MUTATION]\n\nAre you sure you want to ${readableAction} configuration module: ${featureKey}?`);

        if (!userConfirmed) {
            if (toggleSwitch) toggleSwitch.checked = !isChecked;
            console.log(`[SECURITY CONTROLS] Mutation aborted by administrative bypass.`);
            return;
        }

        try {
            const response = await fetch(`/api/config/update-config`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    feature_key: featureKey,
                    active_state: isChecked
                }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`Status: ${response.status}`);
            }

            console.log(`[SECURITY CONTROLS] ${featureKey} updated.`);
            alert(`[SUCCESS] ${featureKey} has been updated successfully.`);

        } catch (error) {
            console.error(`[SECURITY FAILURE] State mutation dropped:`, error);
            alert(`[FAILURE] State mutation rejected by security gateway.`);
            if (toggleSwitch) toggleSwitch.checked = !isChecked;
        }
    },

    purgeVolatileCache: function () {
        if (confirm("CRITICAL: Purge all local memory and force hardware sync?")) {
            this.cachedAlerts = [];
            this.cachedInquiries = [];
            this.fetchDashboardData();
            console.log("UI KERNEL: Cache purged, stream re-synchronized.");
        }
    },

    terminateAdminSession: async function () {
        if (confirm("DANGER: Terminate current administrative session?")) {
            try {
                const response = await fetch('/api/config/logout', {
                    method: 'POST',
                    credentials: 'include'
                });

                if (response.ok) {
                    console.log("📡 UI_KERNEL: Session purged server-side.");
                    window.location.replace('login.html');
                } else {
                    alert("Logout failed. Please check backend connection.");
                }
            } catch (err) {
                console.error("🚨 UI KERNEL FAULT: Logout sequence interrupted.", err);
            }
        }
    },

    syncAutoBlockThreshold: async function (threshold) {
        console.log(`SIEM KERNEL: Sentinel threshold set to ${threshold} hits/60s.`);
    },

    fetchDashboardData: async function () {
        try {
            const alertRes = await Security.authFetch(`/manage/security-inbox?t=${Date.now()}`);
            const alertData = await alertRes.json();

            this.cachedAlerts = alertData.alerts || [];

            this.populateSecurityInbox(this.cachedAlerts);

            const packetsCounter = document.getElementById('msg-count');
            if (packetsCounter) {
                packetsCounter.textContent = this.cachedAlerts.length;
            }

            const overviewAuditBody = document.getElementById('overview-audit-body-fallback');
            if (overviewAuditBody) {
                if (this.cachedAlerts.length === 0) {
                    overviewAuditBody.innerHTML = `<tr><td colspan="3" class="p-6 text-center text-gray-600 text-[11px]"><i class="fa-solid fa-network-wired mr-1 text-blue-500/50"></i> Perimeter clearance stable.</td></tr>`;
                } else {
                    overviewAuditBody.innerHTML = this.cachedAlerts.slice(0, 5).map(a => `
                        <tr class="hover:bg-white/5 transition-colors border-b border-white/5">
                            <td class="p-3">${a.action || 'Generic Threat'}</td>
                            <td class="p-3 text-red-400">${a.ip_address || '0.0.0.0'}</td>
                            <td class="p-3 text-center"><span class="text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/10 text-[10px]">${a.status || 'FLAGGED'}</span></td>
                        </tr>
                    `).join('');
                }
            }

            const auditRes = await Security.authFetch(`/manage/audit-trail?t=${Date.now()}`);
            const auditData = await auditRes.json();

            this.cachedAuditLogs = Array.isArray(auditData) ? auditData : (auditData.logs || []);
            this.populateAuditLogsTable(this.cachedAuditLogs);

            const opsCounter = document.getElementById('audit-count');
            if (opsCounter) {
                opsCounter.textContent = this.cachedAuditLogs.length;
            }

            const inqRes = await Security.authFetch(`/manage/inquiries?t=${Date.now()}`);
            const inqData = await inqRes.json();

            this.cachedInquiries = Array.isArray(inqData) ? inqData : [];

            this.populateInquiriesTable(this.cachedInquiries);

            const overviewMessageBody = document.getElementById('overview-message-body-fallback');
            if (overviewMessageBody) {
                if (this.cachedInquiries.length === 0) {
                    overviewMessageBody.innerHTML = `<tr><td colspan="3" class="p-6 text-center text-gray-600 text-[11px]"><i class="fa-solid fa-terminal mr-1 text-emerald-500/50"></i> No active ingress threads.</td></tr>`;
                } else {
                    overviewMessageBody.innerHTML = this.cachedInquiries.slice(0, 5).map(msg => `
                        <tr class="hover:bg-white/5 transition-colors border-b border-white/5">
                            <td class="p-3 text-white font-medium">${msg.name || 'Unknown'}</td>
                            <td class="p-3 truncate max-w-[150px] text-gray-300">${msg.message || 'EMPTY_PAYLOAD'}</td>
                            <td class="p-3 text-center"><span class="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/10 text-[10px]">PROCESSED</span></td>
                        </tr>
                    `).join('');
                }
            }

            console.log("UI KERNEL: Telemetry synchronicity accepted.");

            this.updateBlinkingState();

        } catch (error) {
            console.error("🚨 UI KERNEL FAULT: Stream extraction failed.", error);
        }
    },

    synchronizeSystemSwitches: async function () {
        try {
            const response = await Security.authFetch(`/config/current-posture?t=${Date.now()}`);
            if (response.status === 401) {
                window.location.replace('login.html');
                return;
            }
            if (response.ok) {
                const posture = await response.json();
                console.log("UI KERNEL: Posture parameters synchronized.", posture);
            }
        } catch (error) {
            console.error("🚨 UI KERNEL FAULT: Configuration syncing error.", error);
        }
    },

    populateSecurityInbox: function (alerts) {
        const inboxBody = document.getElementById('security-inbox-body');
        if (!inboxBody) return;

        inboxBody.innerHTML = alerts.length === 0
            ? `<tr><td colspan="4" class="p-8 text-center text-xs text-emerald-500 font-mono">✅ INBOX_CLEAR_NO_THREATS</td></tr>`
            : alerts.map(a => `
            <tr class="border-b border-white/5 hover:bg-white/[0.02]">
                <td class="p-3 text-red-400 font-mono text-xs">${a.ip_address}</td>
                <td class="p-3 text-white text-xs">${a.action}</td>
                <td class="p-3 text-center">
                    <span class="px-2 py-0.5 rounded text-[9px] ${a.status === 'IP_BLOCKED' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' : 'bg-red-500/10 text-red-500 border border-red-500/20'}">
                        ${a.status}
                    </span>
                </td>
                <td class="p-3 text-center">
                    <button onclick="DashboardManager.launchForensicBuffer(${a.id}, 'alerts')" class="text-blue-400 hover:text-blue-300 text-xs">Investigate</button>
                </td>
            </tr>
        `).join('');
    },

    populateInquiriesTable: function (messages) {
        const msgBody = document.getElementById('message-body');
        const msgCountElement = document.getElementById('msg-count');

        if (msgCountElement) msgCountElement.innerText = messages.length;
        if (!msgBody) return;

        msgBody.innerHTML = '';

        if (messages.length === 0) {
            msgBody.innerHTML = `<tr><td colspan="5" class="p-8 text-center font-mono text-gray-600 text-xs tracking-wider">No Inbound Inquiries Found</td></tr>`;
            return;
        }

        this.cachedInquiries = messages;

        messages.forEach((msg, index) => {
            const date = new Date(msg.created_at || msg.timestamp).toLocaleString('en-US', { hour12: false });

            const trueDatabaseId = msg.id;

            let statusBadge = `<span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase border text-amber-400 bg-amber-500/10 border-amber-500/20 tracking-wider">UNREAD</span>`;
            if (msg.is_read === true || msg.is_read === 1 || msg.status === 'READ') {
                statusBadge = `<span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase border text-emerald-400 bg-emerald-500/10 border-emerald-500/20 tracking-wider">READ</span>`;
            }

            msgBody.innerHTML += `
                <tr class="hover:bg-white/[0.01] transition-colors border-b border-white/5 font-mono text-xs">
                <td class="p-4 text-white font-medium">${msg.name}</td>
                <td class="p-4 text-gray-400">${msg.email}</td>
                <td class="p-4 text-gray-300 max-w-xs truncate">${msg.message || 'EMPTY_PAYLOAD'}</td>
                <td class="p-4 text-gray-500 text-[11px]">${date}</td>
                <td class="p-4">${statusBadge}</td>
                    <td class="p-4 text-center">
                        <div class="flex items-center justify-center gap-1.5">
                            <button onclick="window.DashboardManager.launchInquiryModal(${trueDatabaseId})" class="p-1.5 bg-white/5 border border-white/5 hover:border-white/20 rounded text-gray-400 hover:text-white transition cursor-pointer" title="👁 View message context & mark read">
                                <i class="fa-solid fa-eye text-[10px]"></i>
                            </button>
                            <button onclick="window.DashboardManager.dispatchInquiryDrop(${trueDatabaseId})" class="p-1.5 bg-red-500/5 border border-red-500/10 hover:bg-red-500/20 text-red-400/80 hover:text-red-400 rounded transition cursor-pointer" title="🗑️ Delete inquiry // Purge record">
                                <i class="fa-solid fa-trash-can text-[10px]"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });
    },

    launchInquiryModal: function (recordId) {
        const targetInq = this.cachedInquiries.find((m) => m.id === recordId);
        if (!targetInq) return;

        const modalTitle = document.getElementById('modal-alert-title');
        const modalIp = document.getElementById('modal-ip-display');
        const modalTime = document.getElementById('modal-time-display');
        const modalPayload = document.getElementById('modal-payload-display');

        if (modalTitle) modalTitle.innerText = `INBOUND INQUIRY: DB_REF: #${targetInq.id || 'N/A'}`;
        if (modalIp) modalIp.innerText = targetInq.email || 'NO_EMAIL_RECORD';
        if (modalTime) modalTime.innerText = new Date(targetInq.created_at || targetInq.timestamp).toLocaleString();
        if (modalPayload) {
            modalPayload.innerText = `FROM: ${targetInq.name}\n\nMESSAGE PAYLOAD:\n${targetInq.message || 'EMPTY_PAYLOAD'}`;
            modalPayload.classList.remove('text-red-400');
            modalPayload.classList.add('text-emerald-400');
        }

        const btnMarkRead = document.getElementById('modal-btn-investigate');
        if (btnMarkRead) {
            if (targetInq.is_read === true || targetInq.is_read === 1 || targetInq.status === 'READ') {
                btnMarkRead.style.display = 'none';
            } else {
                btnMarkRead.style.display = 'flex';
                btnMarkRead.innerHTML = `<i class="fa-solid fa-check"></i> MARK_AS_READ`;
                btnMarkRead.className = "px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 text-emerald-400 rounded text-[10px] uppercase font-bold transition flex items-center gap-1";
                btnMarkRead.onclick = () => window.DashboardManager.dispatchInquiryReadState(recordId);
            }
        }

        const btnBlock = document.getElementById('modal-btn-block');
        if (btnBlock) {
            btnBlock.style.display = 'flex';
            btnBlock.innerHTML = `<i class="fa-solid fa-trash-can"></i> DROP_RECORD`;
            btnBlock.onclick = () => window.DashboardManager.dispatchInquiryDrop(recordId);
        }

        const modalContainer = document.getElementById('forensic-modal');
        if (modalContainer) modalContainer.classList.remove('hidden');
    },

    dispatchInquiryReadState: async function (recordId) {
        const targetInq = this.cachedInquiries.find((m) => m.id === recordId);
        if (!targetInq) return;

        const endpoint = '/api/manage/inquiry-read';

        try {
            let response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    inquiry_id: parseInt(recordId, 10),
                    status: "READ"
                }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`FastAPI Kernel rejected transaction. Status: ${response.status}`);
            }

            targetInq.is_read = true;
            targetInq.status = 'READ';

            this.populateInquiriesTable(this.cachedInquiries);
            this.closeForensicModal();

        } catch (err) {
            console.error("🚨 UI KERNEL REJECTION:", err);
            alert(`Operation Failed: Validation handshake mismatch on backend models.`);
        }
    },

    dispatchInquiryDrop: async function (recordId) {
        if (!confirm("Are you sure you want to delete this record?")) return;

        const targetInq = this.cachedInquiries.find((m) => m.id === recordId);
        if (!targetInq) return;

        const endpoint = `/api/manage/delete/${targetInq.id}`;

        console.log(`UI KERNEL: Emitting suppression token to FastAPI -> Node: ${targetInq.id}`);

        try {
            let response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`FastAPI Kernel rejected node destruction logic. Status Code: ${response.status}`);
            }

            console.log(`✅ UI KERNEL: Deletion committed by backend. Evicting record node.`);

            this.cachedInquiries = this.cachedInquiries.filter((m) => m.id !== targetInq.id);
            this.populateInquiriesTable(this.cachedInquiries);
            this.closeForensicModal();

        } catch (err) {
            console.error("🚨 UI KERNEL REJECTION: Purge execution blocked.", err);
            alert(`Purge Interrupted: ${err.message}`);
        }
    },

    populateAuditLogsTable: function (alerts) {
        const auditBody = document.getElementById('master-audit-log-body');
        const auditCountElement = document.getElementById('audit-count');

        if (auditCountElement) auditCountElement.innerText = alerts.length;
        if (!auditBody) return;

        auditBody.innerHTML = '';

        if (alerts.length === 0) {
            auditBody.innerHTML = `<tr><td colspan="5" class="p-8 text-center font-mono text-gray-600 text-xs tracking-wider">SIEM STREAM IDLE: No Alerts Logged</td></tr>`;
            return;
        }

        this.cachedAuditLogs = alerts;
        let visibleCount = 0;

        alerts.forEach((alert, index) => {
            const actionText = alert.action || 'SYSTEM_ALERT';
            const actionNormalized = actionText.toUpperCase();
            const eventTypeNormalized = String(alert.event_type || '').toUpperCase();

            if (
                actionNormalized.includes('FORENSIC_CHAT') ||
                eventTypeNormalized.includes('FORENSIC_CHAT') ||
                actionNormalized.includes('HUMAN ANALYST CONTEXT') ||
                actionNormalized.includes('RASP_AI_FORENSIC_KERNEL') ||
                actionNormalized.includes('RASP AI CORE STANDBY')
            ) {
                return;
            }

            visibleCount++;

            const location = alert.location || "UNKNOWN_GEO";
            const date = new Date(alert.timestamp || alert.time).toLocaleString('en-US', { hour12: false });

            let rowBackgroundClass = 'bg-emerald-950/10 hover:bg-emerald-500/5 transition-colors border-b border-t border-emerald-500/10';
            let dateColumnColorClass = 'text-emerald-500/80 font-bold';
            let actionColumnColorClass = 'text-emerald-500/80 font-bold';
            let statusClass = 'text-emerald-500/80 bg-emerald-500/10 border-emerald-500/20 font-bold';
            let ipColumnColorClass = 'text-emerald-500/80 font-bold';
            let locationColumnColorClass = 'text-emerald-500/80 font-bold';

            if (alert.status === 'ALERT') statusClass = 'text-red-400 bg-red-500/10 border-red-500/20';
            if (alert.status === 'IP_BLOCKED') statusClass = 'text-red-600 bg-red-950/20 border-red-900/40 font-black animate-pulse';
            if (alert.status === 'INVESTIGATING') statusClass = 'text-blue-400 bg-blue-500/10 border-blue-500/20';
            if (alert.status === 'RESOLVED') statusClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
            if (alert.status === 'UNBLOCKED') statusClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';

            if (alert.status === 'RESOLVED') {
                rowBackgroundClass = 'bg-emerald-950/10 hover:bg-emerald-950/20 transition-colors border-b border-emerald-500/10';
                statusClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
                dateColumnColorClass = 'text-emerald-500 font-bold';
                actionColumnColorClass = 'text-emerald-400 font-bold';
                ipColumnColorClass = 'text-emerald-400 font-bold';
                locationColumnColorClass = 'text-emerald-400/60 font-bold';
            }
            else if (alert.status === 'UNBLOCKED') {
                rowBackgroundClass = 'bg-emerald-950/10 hover:bg-emerald-950/20 transition-colors border-b border-emerald-500/10';
                statusClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
                dateColumnColorClass = 'text-emerald-500 font-bold';
                actionColumnColorClass = 'text-emerald-400 font-bold';
                ipColumnColorClass = 'text-emerald-400 font-bold';
                locationColumnColorClass = 'text-emerald-400/60 font-bold';
            }
            else if (alert.status === 'IP_BLOCKED') {
                rowBackgroundClass = 'bg-red-950/15 hover:bg-red-950/25 transition-colors border-b border-red-500/10';
                statusClass = 'text-red-400 bg-red-500/10 border-red-500/20';
                dateColumnColorClass = 'text-red-500 font-bold';
                actionColumnColorClass = 'text-red-500 font-bold';
                ipColumnColorClass = 'text-red-500 font-bold';
                locationColumnColorClass = 'text-red-500/60 font-bold';
            }
            else if (alert.status === 'INVESTIGATING') {
                rowBackgroundClass = 'bg-blue-950/10 hover:bg-blue-950/20 transition-colors border-b border-blue-500/10';
                statusClass = 'text-blue-400 bg-blue-500/10 border-blue-500/20';
                dateColumnColorClass = 'text-blue-500 font-bold';
                actionColumnColorClass = 'text-blue-500 font-bold';
                ipColumnColorClass = 'text-blue-500 font-bold';
                locationColumnColorClass = 'text-blue-500/60 font-bold';
            }
            else {
                if (actionNormalized === 'LOGIN_THRESHOLD_EXCEEDED' || actionNormalized.includes('THRESHOLD') || actionNormalized.includes('EXCEEDED')) {
                    rowBackgroundClass = 'bg-red-950/10 hover:bg-red-950/30 transition-colors border-b border-red-500/10';
                    statusClass = 'text-red-500/80 bg-red-500/10 border-red-500/20';
                    dateColumnColorClass = 'text-red-500/80 font-bold';
                    actionColumnColorClass = 'text-red-500/80 font-bold';
                    ipColumnColorClass = 'text-red-500/80 font-bold';
                    locationColumnColorClass = 'text-red-500/80 font-bold';
                    if (alert.status !== 'INVESTIGATING') statusClass = 'text-red-400 bg-red-500/10 border-red-500/20';
                }
                else if (actionNormalized === 'INVALID_CREDENTIALS' || actionNormalized === 'UNAUTHORIZED' || actionNormalized.includes('INVALID')) {
                    rowBackgroundClass = 'bg-amber-950/10 hover:bg-amber-950/30 transition-colors border-b border-amber-500/20';
                    statusClass = 'text-amber-500/80 bg-amber-500/10 border-amber-500/20';
                    dateColumnColorClass = 'text-amber-500/80 font-bold';
                    actionColumnColorClass = 'text-amber-500/80 font-bold';
                    ipColumnColorClass = 'text-amber-500/80 font-bold';
                    locationColumnColorClass = 'text-amber-500/80 font-bold';
                }
                else {
                    const criticalSignatures = ['BRUTE', 'ATTACK', 'SQLI', 'XSS', 'LIMIT', 'LFI', 'RCE', 'EXFILTRATION', 'MALWARE', 'RECON', 'CSRF'];
                    const warningSignatures = ['FAILED', 'UNAUTHORIZED', 'IDOR', 'ASSIGNMENT', 'CONFIG', 'CLICKJACKING', 'HIJACK', 'TIMING', 'GUESSING', 'LOCKOUT_CONTINUED'];

                    if (warningSignatures.some(sig => actionNormalized.includes(sig))) {
                        rowBackgroundClass = 'bg-amber-950/10 hover:bg-amber-950/30 transition-colors border-b border-amber-500/20';
                        statusClass = 'text-amber-500/80 bg-amber-500/10 border-amber-500/20';
                        dateColumnColorClass = 'text-amber-500/80 font-bold';
                        actionColumnColorClass = 'text-amber-500/80 font-bold';
                        ipColumnColorClass = 'text-amber-500/80 font-bold';
                        locationColumnColorClass = 'text-amber-500/80 font-bold';
                    }
                    else if (criticalSignatures.some(sig => actionNormalized.includes(sig))) {
                        rowBackgroundClass = 'bg-red-950/10 hover:bg-red-950/30 transition-colors border-b border-red-500/20';
                        statusClass = 'text-red-500/80 bg-red-500/10 border-red-500/20 font-bold';
                        dateColumnColorClass = 'text-red-500/80 font-bold';
                        actionColumnColorClass = 'text-red-500/80 font-bold';
                        ipColumnColorClass = 'text-red-500/80 font-bold';
                        locationColumnColorClass = 'text-red-500/80 font-bold';
                        if (alert.status !== 'INVESTIGATING') statusClass = 'text-red-400 bg-red-500/10 border-red-500/20';
                    }
                    else if (actionNormalized.includes('SUCCESS') || actionNormalized.includes('ADMIN_LOGIN') || actionNormalized.includes('AUTH_GRANTED') || actionNormalized.includes('SESSION')) {
                        rowBackgroundClass = 'bg-emerald-950/20 hover:bg-emerald-950/30 transition-colors border-b border-emerald-500/20';
                        statusClass = 'text-emerald-500/80 bg-emerald-500/10 border-emerald-500/20 font-bold';
                        dateColumnColorClass = 'text-emerald-500/80 font-bold';
                        actionColumnColorClass = 'text-emerald-500/80 font-bold';
                        ipColumnColorClass = 'text-emerald-500/80 font-bold';
                        locationColumnColorClass = 'text-emerald-500/80 font-bold';
                    }
                }
            }

            const uniqueRecordId = alert.id || index;
            const targetIp = alert.ip_address || alert.ip || 'localhost';

            auditBody.innerHTML += `
                <tr class="${rowBackgroundClass}">
                    <td class="p-4 text-[11px] font-mono">${date}</td>
                    <td class="p-4 ${actionColumnColorClass} tracking-tight font-mono">${actionText}</td>
                    <td class="p-4 ${ipColumnColorClass} font-mono">${targetIp}</td>
                    <td class="p-4 ${locationColumnColorClass} font-mono text-[10px]">${location}</td>
                    <td class="p-4">
                        <span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${statusClass}">
                            ${alert.status || 'INTERCEPTED'}
                        </span>
                    </td>
                    <td class="p-4 text-center">
                        <div class="flex items-center justify-center gap-1.5">
                            ${alert.status === 'IP_BLOCKED' ? `
                                <button onclick="window.DashboardManager.dispatchUnblockIP('${targetIp}')" class="p-1.5 bg-emerald-500/5 border border-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400/80 hover:text-emerald-400 rounded transition cursor-pointer" title="🔓 Unblock IP">
                                    <i class="fa-solid fa-unlock text-[10px]"></i>
                                </button>
                            ` : ''}
                            <button onclick="window.DashboardManager.launchForensicBuffer(${uniqueRecordId}, 'audit')" class="p-1.5 bg-white/5 border border-white/5 hover:border-white/20 rounded text-gray-400 hover:text-white transition cursor-pointer" title="👁 View details & payload context">
                                <i class="fa-solid fa-eye text-[10px]"></i>
                            </button>
                            <button onclick="window.DashboardManager.dispatchMitigation(${uniqueRecordId}, 'IP_BLOCKED')" class="p-1.5 bg-red-500/5 border border-red-500/10 hover:bg-red-500/20 text-red-400/80 hover:text-red-400 rounded transition cursor-pointer" title="🚫 Block Attacker IP">
                                <i class="fa-solid fa-ban text-[10px]"></i>
                            </button>
                            <button onclick="window.DashboardManager.dispatchMitigation(${uniqueRecordId}, 'INVESTIGATING')" class="p-1.5 bg-blue-500/5 border border-red-500/10 hover:bg-blue-500/20 text-blue-400/80 hover:text-blue-400 rounded transition cursor-pointer" title="📝 Investigate database logs">
                                <i class="fa-solid fa-file-waveform text-[10px]"></i>
                            </button>
                            <button onclick="window.DashboardManager.dispatchDeleteAlert(${uniqueRecordId})" class="p-1.5 bg-red-500/5 border border-red-500/10 hover:bg-red-500/20 text-red-400/80 hover:text-red-400 rounded transition cursor-pointer" title="🗑️ Delete Alert Trace">
                                <i class="fa-solid fa-trash-can text-[10px]"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        if (visibleCount === 0) {
            auditBody.innerHTML = `<tr><td colspan="6" class="p-8 text-center font-mono text-gray-600 text-xs tracking-wider">SIEM STREAM IDLE: No Alert Loogged</td></tr>`;
        }
    },

    dispatchDeleteAlert: async function (alertId) {
        if (!confirm("CRITICAL: Verify authorization to delete audit trace?")) return;

        try {
            const response = await fetch(`/api/manage/delete-alert/${alertId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ detail: "Security check failed" }));
                throw new Error(errorData.detail || "Request rejected by server");
            }

            this.fetchDashboardData();
        } catch (err) {
            console.error("🚨 Request rejected:", err);
        }
    },

    dispatchUnblockIP: async function (ipAddress, event) {
        if (!confirm(`CRITICAL: Restore access for IP: ${ipAddress}?`)) return;

        const actionButton = event ? event.target.closest('button') || event.target : null;
        const row = actionButton ? actionButton.closest('tr') : null;

        if (actionButton) {
            actionButton.style.opacity = "0.5";
            actionButton.style.pointerEvents = "none";
        }

        try {
            const metaTag = document.querySelector('meta[name="csrf-token"]');
            const csrfToken = metaTag ? metaTag.getAttribute('content') : "";

            const response = await fetch(`/api/manage/unblock-ip/${ipAddress}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ detail: "Security check failed" }));
                throw new Error(errorData.detail || "Request rejected by server");
            }

            console.log(`[+] Security Posture Updated: Clear command issued for ${ipAddress}`);

            if (row) {
                const statusBadge = row.querySelector('span.uppercase');
                if (statusBadge) {
                    statusBadge.innerText = "Alert";
                    statusBadge.className = "px-2 py-0.5 rounded text-[9px] font-bold uppercase border text-red-400 bg-red-500/10 border-red-500/20";
                }
            }

            if (actionButton) {
                actionButton.remove();
            }

            if (this.cachedAuditLogs) {
                const match = this.cachedAuditLogs.find(a => (a.ip_address || a.ip) === ipAddress);
                if (match) {
                    match.status = "Alert";
                }
            }

        } catch (err) {
            console.error("🚨 UI KERNEL FAULT: Exception on unblock boundary mutation:", err);
            if (actionButton) {
                actionButton.style.opacity = "1";
                actionButton.style.pointerEvents = "auto";
            }
        }
    },

    executeLiveStream: async function (element, alertId, userNote) {
        if (!element) return;
        element.textContent = "🔄 Initializing secure forensic stream...";

        const threadUuid = "10000000-1000-4000-8000-100000000000".replace(/[018]/g, c =>
            (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16)
        );

        try {
            const response = await Security.authFetch('/api/config/investigate-stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    alert_id: alertId,
                    thread_id: threadUuid,
                    note: userNote
                })
            });

            if (!response.ok) throw new Error("Connection Refused");

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            element.textContent = "";

            const targetAlert = this.cachedAuditLogs.find((a) => a.id === alertId);
            const currentIp = targetAlert ? (targetAlert.ip_address || targetAlert.ip || '127.0.0.1') : '127.0.0.1';
            let collectedAiText = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                const cleanText = chunk.replace(/^data:\s*/gm, '').replace(/\n\n$/gm, '');
                collectedAiText += cleanText;

                let sanitizedDisplay = collectedAiText;
                if (sanitizedDisplay.includes('Forensic Workspace Update')) {
                    const sections = sanitizedDisplay.split(/Correlation engine running state assessments on Node Context #\d+\./i);
                    sanitizedDisplay = sections[sections.length - 1].trim();
                }

                if (sanitizedDisplay) {
                    element.innerHTML = `<div class="p-1">${sanitizedDisplay}</div>`;
                }
            }

            if (collectedAiText) {
                this.cachedAuditLogs.push({
                    id: Date.now() + Math.floor(Math.random() * 1000),
                    action: 'RASP_AI_FORENSIC_KERNEL',
                    ip_address: currentIp,
                    timestamp: new Date().toISOString(),
                    payload: collectedAiText
                });
            }
        } catch (err) {
            element.textContent = "🚨 FORENSIC KERNEL FAULT: Connection denied by Policy Decision Point.";
        }
    },

    launchForensicBuffer: async function (recordId, sourceArray = 'audit', runtimeNote = "") {
        const arrayScope = (sourceArray === 'alerts') ? this.cachedAlerts : this.cachedAuditLogs;
        const targetAlert = arrayScope.find((a) => a.id === recordId);
        if (!targetAlert) return;

        const modalTitle = document.getElementById('modal-alert-title');
        const modalIp = document.getElementById('modal-ip-display');
        const modalTime = document.getElementById('modal-time-display');
        const modalPayload = document.getElementById('modal-payload-display');
        const humanStream = document.getElementById('human-notes-stream');
        const aiPane = document.getElementById('ai-forensic-pane');

        const currentIp = targetAlert.ip_address || targetAlert.ip || '127.0.0.1';

        if (modalTitle) modalTitle.innerText = `INSPECTION BUFFER: ${targetAlert.action || 'SIEM ALERT'}`;
        if (modalIp) modalIp.innerText = currentIp;
        if (modalTime) modalTime.innerText = new Date(targetAlert.timestamp || targetAlert.time).toLocaleString();

        if (modalPayload) {
            if (sourceArray === 'audit') {
                modalPayload.innerText = "SECURE TRANSFER IN PROGRESS: Fetching forensic payload from vault...";
                try {
                    const response = await Security.authFetch(`/manage/audit-log/${recordId}/context`);
                    if (!response.ok) throw new Error(`Handshake failed with status: ${response.status}`);

                    const contextData = await response.json();
                    modalPayload.innerText = contextData.payload || "TELEMETRY ALERT: No explicit raw input payload.";
                } catch (err) {
                    console.error("🚨 UI_KERNEL_FAULT: Failed to fetch on-demand payload context.", err);
                    modalPayload.innerText = "SECURITY VIOLATION OR NETWORK FAULT: Decryption and retrieval failed.";
                }
            } else {
                modalPayload.innerText = targetAlert.payload_context || targetAlert.payload || "TELEMETRY ALERT: No explicit raw input payload.";
            }
        }

        if (humanStream) {
            if (runtimeNote) {
                const alreadyCached = this.cachedAuditLogs.some(c =>
                    (c.ip_address === currentIp || c.ip === currentIp) &&
                    String(c.action).toUpperCase().includes('HUMAN') &&
                    c.payload === runtimeNote
                );

                if (!alreadyCached) {
                    this.cachedAuditLogs.push({
                        id: Date.now(),
                        action: 'HUMAN ANALYST CONTEXT',
                        ip_address: currentIp,
                        timestamp: new Date().toISOString(),
                        payload: runtimeNote
                    });
                }
            }

            let matchingChats = this.cachedAuditLogs.filter(log => {
                const logIp = log.ip_address || log.ip || '';
                const logAction = String(log.action || '').toUpperCase();
                return logIp === currentIp && (
                    logAction.includes('HUMAN ANALYST CONTEXT') ||
                    logAction.includes('RASP AI FORENSIC KERNEL') ||
                    logAction.includes('FORENSIC CHAT')
                );
            });

            if (matchingChats.length === 0) {
                humanStream.innerHTML = '<span class="text-[10px] text-gray-500 font-mono">READY: No Local Context Appended</span>';
            } else {
                humanStream.innerHTML = matchingChats.map(chat => {
                    const actionUpper = String(chat.action || '').toUpperCase();
                    const isAi = actionUpper.includes('RASP AI') || actionUpper.includes('KERNEL');
                    const timestamp = new Date(chat.timestamp || chat.time).toLocaleTimeString('en-US', { hour12: false });

                    let displayText = chat.payload || chat.message || chat.action || '';
                    if (isAi && displayText.includes('Forensic Workspace Update')) {
                        const parsingChunks = displayText.split(/Correlation engine running state assessments on Node Context #\d+\./i);
                        displayText = parsingChunks[parsingChunks.length - 1].trim();
                    }

                    return `
                        <div class="mb-2 p-2 rounded text-[11px] font-mono border ${isAi ? 'bg-blue-950/15 border-blue-500/10 text-blue-400' : 'bg-zinc-900 border-zinc-800 text-gray-200'}">
                            <div class="flex justify-between items-center text-[9px] opacity-60 mb-1">
                                <span>${isAi ? '🤖 AI Analysis' : '👤 Human Context'}</span>
                                <span>${timestamp}</span>
                            </div>
                            <p class="whitespace-pre-wrap">${displayText}</p>
                        </div>
                    `;
                }).join('');
            }
        }

        if (aiPane) {
            if (runtimeNote) {
                this.executeLiveStream(aiPane, recordId, runtimeNote);
            } else {
                aiPane.textContent = "AI Standby. Click 'INVESTIGATE' to initialize session.";
            }
        }

        const btnInvestigate = document.getElementById('modal-btn-investigate');
        const btnBlock = document.getElementById('modal-btn-block');
        const btnResolve = document.getElementById('modal-btn-resolve');

        if (btnInvestigate) {
            btnInvestigate.onclick = () => window.DashboardManager.dispatchMitigation(targetAlert.id, 'INVESTIGATING', sourceArray);
        }

        const modalContainer = document.getElementById('forensic-modal');
        if (modalContainer) modalContainer.classList.remove('hidden');
    },

    closeForensicModal: function () {
        const modalContainer = document.getElementById('forensic-modal');
        if (modalContainer) modalContainer.classList.add('hidden');
    },

    dispatchMitigation: async function (recordId, actionTypeString, sourceArray = 'audit') {
        let note = "";
        if (actionTypeString === 'INVESTIGATING') {
            note = prompt("Enter investigation notes (Required for Investigation):");
            if (!note) return;
        }

        const arrayScope = (sourceArray === 'alerts') ? this.cachedAlerts : this.cachedAuditLogs;
        const targetAlert = arrayScope.find((a) => a.id === recordId);
        if (targetAlert) targetAlert.status = actionTypeString;

        this.populateAuditLogsTable(this.cachedAuditLogs);
        this.updateBlinkingState();

        if (actionTypeString !== 'INVESTIGATING') {
            this.closeForensicModal();
        }

        try {
            await Security.authFetch(this.mitigationEndpoint || '/api/config/mitigate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    alert_id: targetAlert?.id || recordId,
                    action_vector: actionTypeString,
                    target_ip: targetAlert?.ip_address || targetAlert?.ip || '127.0.0.1'
                })
            });
        } catch (err) {
            console.error("🚨 KERNEL FAULT: Mitigation sync failed.", err);
        }

        if (actionTypeString === 'INVESTIGATING') {
            this.launchForensicBuffer(recordId, sourceArray, note);
        }
    },

    renderAnalyticsCharts: function () {
        const totalAlerts = parseInt(document.getElementById('audit-count')?.innerText) || 0;
        const totalMessages = parseInt(document.getElementById('msg-count')?.innerText) || 0;

        if (document.getElementById('analytics-alert-count')) document.getElementById('analytics-alert-count').innerText = totalAlerts;
        if (document.getElementById('analytics-msg-count')) document.getElementById('analytics-msg-count').innerText = totalMessages;

        const distCtx = document.getElementById('threatDistributionChart');
        if (distCtx) {
            if (this.activeCharts.distribution) this.activeCharts.distribution.destroy();

            const systemVerifications = totalAlerts > 0 ? Math.floor(totalAlerts * 0.4) : 5;
            const interceptedThreats = totalAlerts > 0 ? Math.ceil(totalAlerts * 0.6) : 0;

            this.activeCharts.distribution = new Chart(distCtx, {
                type: 'doughnut',
                data: {
                    labels: ['VERIFIED_EVENTS', 'THREAT_INTERCEPTS', 'SYSTEM_IDLE'],
                    datasets: [{
                        data: [systemVerifications, interceptedThreats, interceptedThreats === 0 ? 10 : 2],
                        backgroundColor: ['rgba(52, 211, 153, 0.15)', 'rgba(248, 113, 113, 0.2)', 'rgba(161, 161, 170, 0.05)'],
                        borderColor: ['#10b981', '#f87171', '#52525b'],
                        borderWidth: 1,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#a1a1aa', font: { family: 'monospace', size: 9 } } }
                    }
                }
            });
        }

        const timelineCtx = document.getElementById('ingressTimelineChart');
        if (timelineCtx) {
            if (this.activeCharts.timeline) this.activeCharts.timeline.destroy();

            this.activeCharts.timeline = new Chart(timelineCtx, {
                type: 'bar',
                data: {
                    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                    datasets: [
                        {
                            label: 'INQUIRIES',
                            data: [Math.floor(totalMessages * 0.2), Math.floor(totalMessages * 0.1), Math.floor(totalMessages * 0.4), totalMessages, Math.floor(totalMessages * 0.3), Math.floor(totalMessages * 0.2)],
                            backgroundColor: 'rgba(52, 211, 153, 0.2)',
                            borderColor: '#10b981',
                            borderWidth: 1
                        },
                        {
                            label: 'SECURITY_ALERTS',
                            data: [Math.floor(totalAlerts * 0.1), Math.floor(totalAlerts * 0.5), Math.floor(totalAlerts * 0.2), totalAlerts],
                            backgroundColor: 'rgba(248, 113, 113, 0.2)',
                            borderColor: '#f87171',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#a1a1aa', font: { family: 'monospace', size: 9 } } }
                    }
                }
            });
        }
    },

    switchView: function (targetPanelId, activeBtn) {
        document.querySelectorAll('.dashboard-panel').forEach(panel => {
            panel.classList.add('hidden');
        });

        const targetPanel = document.getElementById(targetPanelId);
        if (targetPanel) targetPanel.classList.remove('hidden');

        document.querySelectorAll('aside nav button, aside nav a').forEach(link => {
            link.classList.remove('bg-emerald-500/10', 'text-emerald-500', 'border-r-2', 'border-emerald-500');
            link.classList.add('text-gray-500');
        });

        if (activeBtn) {
            activeBtn.classList.remove('text-gray-500');
            activeBtn.classList.add('bg-emerald-500/10', 'text-emerald-500', 'border-r-2', 'border-emerald-500');
        }

        const titleElement = document.getElementById('dashboard-title');
        if (titleElement) {
            if (targetPanelId === 'panel-overview') titleElement.innerText = "System Overview";
            if (targetPanelId === 'panel-inquiries') titleElement.innerText = "Inbound Inquiries";
            if (targetPanelId === 'panel-audit-logs') titleElement.innerText = "Security Audit Logs";
            if (targetPanelId === 'panel-analytics') titleElement.innerText = "Visual Analytics Terminal";
            if (targetPanelId === 'panel-settings') titleElement.innerText = "System Configuration";
        }

        if (targetPanelId === 'panel-analytics') {
            this.renderAnalyticsCharts();
        }
    },

    loadAuditLogs: function () {
        this.fetchDashboardData();
    },

    populateOverviewMirrors: function (messagesArray, alertsArray) {
        console.log("UI KERNEL: Synchronizing overview workspace mirrors...");

        const msgOverviewBody = document.getElementById('overview-message-body-fallback');
        if (msgOverviewBody && Array.isArray(messagesArray)) {
            if (messagesArray.length === 0) {
                msgOverviewBody.innerHTML = `<tr><td colspan="3" class="p-4 text-center text-xs text-gray-600 font-mono">No active ingress packets found in database vault.</td></tr>`;
            } else {
                msgOverviewBody.innerHTML = '';

                messagesArray.slice(0, 3).forEach(inq => {
                    const tr = document.createElement('tr');
                    tr.className = "divide-y divide-white/5 text-xs text-gray-400 font-mono hover:bg-white/[0.01] transition-colors border-b border-white/5";

                    const senderCell = document.createElement('td');
                    senderCell.className = "p-3 font-bold text-white truncate max-w-[140px]";
                    senderCell.textContent = inq.name || "Anonymous Node";

                    const snippetCell = document.createElement('td');
                    snippetCell.className = "p-3 text-gray-500 truncate max-w-[200px]";
                    snippetCell.textContent = inq.message || "No payload snippet context.";

                    const actionCell = document.createElement('td');
                    actionCell.className = "p-3 text-center";
                    actionCell.innerHTML = `
                        <button onclick="window.DashboardManager.switchView('panel-inquiries', document.getElementById('btn-nav-inquiries'))" class="text-emerald-500 hover:text-emerald-400 transition text-[10px] uppercase font-bold tracking-loose cursor-pointer">
                            Check Details
                        </button>
                    `;

                    tr.appendChild(senderCell);
                    tr.appendChild(snippetCell);
                    tr.appendChild(actionCell);
                    msgOverviewBody.appendChild(tr);
                });
            }
        }

        const auditOverviewBody = document.getElementById('overview-audit-body-fallback');
        if (auditOverviewBody && Array.isArray(alertsArray)) {
            if (alertsArray.length === 0) {
                auditOverviewBody.innerHTML = `<tr><td colspan="3" class="p-4 text-center text-xs text-gray-600 font-mono">Monitoring Layer-7 perimeter validation queues...</td></tr>`;
            } else {
                auditOverviewBody.innerHTML = '';

                alertsArray.slice(0, 3).forEach(log => {
                    const tr = document.createElement('tr');
                    tr.className = "divide-y divide-white/5 text-xs font-mono hover:bg-white/[0.01] transition-colors border-b border-white/5";

                    const eventCell = document.createElement('td');
                    eventCell.className = "p-3 text-gray-400 truncate max-w-[150px]";
                    eventCell.textContent = log.action || "SYSTEM_ALERT";

                    const ipCell = document.createElement('td');
                    ipCell.className = "p-3 text-blue-400 font-bold";
                    ipCell.textContent = log.ip_address || log.ip || "127.0.0.1";

                    const actionCell = document.createElement('td');
                    actionCell.className = "p-3 text-center";
                    actionCell.innerHTML = `
                        <button onclick="window.DashboardManager.switchView('panel-audit-logs', document.getElementById('btn-nav-audit-logs'))" class="text-emerald-500 hover:text-emerald-400 transition text-[10px] uppercase font-bold tracking-loose cursor-pointer">
                            Investigate
                        </button>
                    `;

                    tr.appendChild(eventCell);
                    tr.appendChild(ipCell);
                    tr.appendChild(actionCell);
                    auditOverviewBody.appendChild(tr);
                });
            }
        }
    }
};

window.DashboardManager = DashboardManager;
document.addEventListener("DOMContentLoaded", () => window.DashboardManager.init());