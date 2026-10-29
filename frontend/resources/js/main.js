document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        lucide.createIcons();
    }

    const nav = document.querySelector('nav');
    if (nav) {
        window.addEventListener('scroll', () => {
            if (window.scrollY > 50) {
                nav.classList.add('shadow-2xl', 'border-b', 'border-emerald-500/20', 'bg-[#0f0f0f]');
            } else {
                nav.classList.remove('shadow-2xl', 'border-b', 'border-emerald-500/20');
            }
        });
    }

    const observerOptions = {
        threshold: 0.1,
        rootMargin: "0px 0px -20px 0px"
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
            } else {
                entry.target.classList.remove('active');
            }
        });
    }, observerOptions);

    document.querySelectorAll('.reveal').forEach((el) => {
        observer.observe(el);
        const rect = el.getBoundingClientRect();
        if (rect.top < window.innerHeight) {
            el.classList.add('active');
        }
    });

    // Attach click listener for Toggle Projects Button (#btn-toggle-projects)
    const toggleBtn = document.getElementById("btn-toggle-projects");
    if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
            if (typeof toggleProjectsSection === "function") {
                toggleProjectsSection();
            }
        });
    }

    // Attach click listeners to open report buttons
    const reportButtons = document.querySelectorAll(".btn-open-report");
    reportButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const reportType = btn.getAttribute("data-report");
            if (reportType) {
                openReportModal(reportType);
            }
        });
    });

    // Event delegation for dynamically rendered gallery image clicks
    document.body.addEventListener("click", (e) => {
        const galleryCard = e.target.closest("[data-image-index]");
        if (galleryCard) {
            const index = parseInt(galleryCard.getAttribute("data-image-index"), 10);
            if (!isNaN(index)) {
                openImageLightbox(index);
            }
        }
    });

    // Attach click listeners to close report modal buttons
    const closeBtnX = document.getElementById("btn-close-report-x");
    const closeBtnFooter = document.getElementById("btn-close-report-footer");

    if (closeBtnX) closeBtnX.addEventListener("click", closeReportModal);
    if (closeBtnFooter) closeBtnFooter.addEventListener("click", closeReportModal);
});

function toggleProjectsSection() {
    const projectsSection = document.getElementById('projects-section');
    if (projectsSection) {
        projectsSection.classList.toggle('hidden');
        if (!projectsSection.classList.contains('hidden')) {
            projectsSection.scrollIntoView({ behavior: 'smooth' });
        }
    }
}

// Global Image Lightbox State & Controls
window.currentImageGallery = [];
window.currentImageIndex = 0;

function openImageLightbox(index) {
    if (!window.currentImageGallery || window.currentImageGallery.length === 0) return;

    window.currentImageIndex = index;

    let lightbox = document.getElementById('lightbox-modal');
    if (!lightbox) {
        lightbox = document.createElement('div');
        lightbox.id = 'lightbox-modal';
        lightbox.className = 'fixed inset-0 bg-black/90 backdrop-blur-md z-[100] flex flex-col items-center justify-center p-4 select-none';
        lightbox.innerHTML = `
            <!-- Close Button -->
            <button id="lightbox-close-btn" class="absolute top-5 right-5 text-gray-400 hover:text-white bg-black/50 border border-white/20 p-2.5 rounded-full transition cursor-pointer z-[110]" aria-label="Close Lightbox">
                <i class="fa-solid fa-xmark text-xl"></i>
            </button>

            <!-- Navigation Buttons -->
            <button id="lightbox-prev-btn" class="absolute left-4 top-1/2 -translate-y-1/2 text-emerald-400 hover:text-white bg-black/60 border border-emerald-500/30 hover:border-emerald-500 p-3 rounded-full transition cursor-pointer z-[110]" aria-label="Previous Image">
                <i class="fa-solid fa-chevron-left text-lg"></i>
            </button>

            <button id="lightbox-next-btn" class="absolute right-4 top-1/2 -translate-y-1/2 text-emerald-400 hover:text-white bg-black/60 border border-emerald-500/30 hover:border-emerald-500 p-3 rounded-full transition cursor-pointer z-[110]" aria-label="Next Image">
                <i class="fa-solid fa-chevron-right text-lg"></i>
            </button>

            <!-- Image View Area -->
            <div class="relative max-w-5xl max-h-[80vh] flex flex-col items-center justify-center">
                <img id="lightbox-image" src="" alt="Proof Display" class="max-w-full max-h-[75vh] object-contain rounded border border-emerald-500/30 shadow-2xl" />
                <span id="lightbox-counter" class="mt-4 text-xs font-mono text-emerald-400 bg-black/70 border border-emerald-500/20 px-3 py-1 rounded-full"></span>
            </div>
        `;
        document.body.appendChild(lightbox);

        // CSP-compliant Event Listeners for Lightbox Controls
        document.getElementById('lightbox-close-btn')?.addEventListener('click', closeImageLightbox);
        document.getElementById('lightbox-prev-btn')?.addEventListener('click', prevLightboxImage);
        document.getElementById('lightbox-next-btn')?.addEventListener('click', nextLightboxImage);

        // Keyboard Navigation (ESC, Left, Right)
        window.addEventListener('keydown', (e) => {
            const activeLightbox = document.getElementById('lightbox-modal');
            if (activeLightbox && !activeLightbox.classList.contains('hidden')) {
                if (e.key === 'Escape') closeImageLightbox();
                if (e.key === 'ArrowLeft') prevLightboxImage();
                if (e.key === 'ArrowRight') nextLightboxImage();
            }
        });
    }

    updateLightboxContent();
    lightbox.classList.remove('hidden');
}

function updateLightboxContent() {
    const imgEl = document.getElementById('lightbox-image');
    const counterEl = document.getElementById('lightbox-counter');
    const prevBtn = document.getElementById('lightbox-prev-btn');
    const nextBtn = document.getElementById('lightbox-next-btn');

    if (imgEl && window.currentImageGallery.length > 0) {
        imgEl.src = window.currentImageGallery[window.currentImageIndex];
        if (counterEl) {
            counterEl.textContent = `PROOF ${window.currentImageIndex + 1} / ${window.currentImageGallery.length}`;
        }
    }

    if (prevBtn && nextBtn) {
        if (window.currentImageGallery.length <= 1) {
            prevBtn.style.display = 'none';
            nextBtn.style.display = 'none';
        } else {
            prevBtn.style.display = 'block';
            nextBtn.style.display = 'block';
        }
    }
}

function prevLightboxImage() {
    if (window.currentImageGallery.length <= 1) return;
    window.currentImageIndex = (window.currentImageIndex - 1 + window.currentImageGallery.length) % window.currentImageGallery.length;
    updateLightboxContent();
}

function nextLightboxImage() {
    if (window.currentImageGallery.length <= 1) return;
    window.currentImageIndex = (window.currentImageIndex + 1) % window.currentImageGallery.length;
    updateLightboxContent();
}

function closeImageLightbox() {
    const lightbox = document.getElementById('lightbox-modal');
    if (lightbox) {
        lightbox.classList.add('hidden');
    }
}

// Render dynamic gallery grid using data attributes for click handling
function renderImageGallery(images = []) {
    if (!images || images.length === 0) return '';

    window.currentImageGallery = images;
    const gridCols = images.length === 1 ? 'grid-cols-1' : 'grid-cols-1 md:grid-cols-2';

    const imageElements = images.map((src, index) => `
        <div class="relative group rounded border border-emerald-500/30 overflow-hidden bg-black/60 flex items-center justify-center cursor-pointer min-h-[140px]" data-image-index="${index}">
            <img 
                src="${src}" 
                alt="Proof Image ${index + 1}" 
                class="w-full h-auto max-h-64 object-cover block group-hover:scale-105 transition-all duration-300" 
                onerror="this.onerror=null; this.classList.add('hidden'); if(this.nextElementSibling) this.nextElementSibling.classList.remove('hidden');" 
            />
            <!-- Fallback element displayed if image path fails -->
            <div class="hidden flex flex-col items-center justify-center p-4 text-center">
                <i class="fa-solid fa-triangle-exclamation text-amber-500 text-xl mb-1"></i>
                <span class="text-[10px] text-gray-400 font-mono">Image Not Found</span>
                <span class="text-[9px] text-gray-500 font-mono truncate max-w-[180px]">${src}</span>
            </div>
            
            <div class="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                <span class="text-[10px] font-mono bg-emerald-600 text-black px-2.5 py-1 font-bold uppercase rounded-xs shadow">
                    <i class="fa-solid fa-expand mr-1"></i> Expand Proof
                </span>
            </div>
        </div>
    `).join('');

    return `<div class="grid ${gridCols} gap-3 mb-4">${imageElements}</div>`;
}

// Project Modal Functions
function openReportModal(type) {
    const modal = document.getElementById('project-report-modal');
    const title = document.getElementById('modal-project-title');
    const content = document.getElementById('modal-project-content');

    if (!modal || !title || !content) return;

    if (type === 'siem') {
        title.textContent = 'CUSTOM BUILT SIEM';

        const siemImages = [
            'resources/screenshots/overview.png',
            'resources/screenshots/alert-and-incident.png',
            'resources/screenshots/auditlogs.png',
            'resources/screenshots/analytics.png',
            'resources/screenshots/investigation-modal.png',
            'resources/screenshots/settings.png',
            'resources/screenshots/settings2.png',
            'resources/screenshots/docker.png',
            'resources/screenshots/events.png',
            'resources/screenshots/uvicorn.png',
            'resources/screenshots/uvicon2.png',
            'resources/screenshots/investigation-stream.png',
            'resources/screenshots/uvicorn_.png',
            'resources/screenshots/audit-trails.png',
        ];

        const galleryHtml = typeof renderImageGallery === 'function' ? renderImageGallery(siemImages) : '';

        content.innerHTML = `
          ${galleryHtml}

          <p class="text-white font-bold">Execution Summary:</p>
          <p class="text-gray-400">Deployed a custom SIEM environment and SSH brute-force monitor (brute_monitor.sh) on Kali Linux to detect rate-limit anomalies. Integrated local log streams into a custom Python AI script connecting to the Gemini API for analyzing attack vectors.</p>

          <p class="text-white font-bold mt-2">Verification Log Output:</p>
          <pre class="bg-black p-3 border border-emerald-500/20 text-emerald-400 rounded text-[11px] overflow-x-auto">
          [+] Ingested 1,420 events from local auth logs
          [+] Threat Detected: IP 198.51.100.42 exceeding rate limits.
          [+] Gemini AI Summary: High probability SSH brute-force payload recognized.
          [+] Action Taken: THREAT_DETECTED: SSH_BRUTEFORCE_MITIGATION logged for investigation.</pre>
        `;
    } else if (type === 'devsecops') {
        title.textContent = 'DEVSECOPS CI/CD PIPELINE';
        const devsecopsImages = [
            'resources/screenshots/devops.png',
            'resources/screenshots/devops2.png',
            'resources/screenshots/devops3.png',
        ];

        const galleryHtml = typeof renderImageGallery === 'function' ? renderImageGallery(devsecopsImages) : '';

        content.innerHTML = `
          ${galleryHtml}

          <p class="text-white font-bold">Quality Gate Status: PASSED</p>
          <p class="text-gray-400">Automated static code analysis (Semgrep), (SonarQube) and dynamic testing (OWASP ZAP) executed prior to Docker container build deployment.</p>

          <p class="text-white font-bold mt-2">Audit Pipeline Output:</p>
          <pre class="bg-black p-3 border border-emerald-500/20 text-emerald-400 rounded text-[11px] overflow-x-auto">[INFO] Semgrep, SonarQube SAST scan finished: 0 Critical, 0 High Security Bugs.
          [INFO] Executing OWASP ZAP DAST against endpoint: https://localhost:8443
          [INFO] TLS Certificate Verification: VALID
          [SUCCESS] DevSecOps Quality Gate compliant. Deployment authorized.</pre>
        `;
    } else if (type === 'access_control') {
        title.textContent = 'ZERO TRUST ACCESS CONTROL AUDIT';

        const accessImages = [
            './resources/screenshots/access-control1.png',
            './resources/screenshots/access-control2.png',
        ];

        const galleryHtml = typeof renderImageGallery === 'function' ? renderImageGallery(accessImages) : '';

        content.innerHTML = `
          ${galleryHtml}

          <p class="text-white font-bold">Vulnerability Target: OWASP Juice Shop & Custom Web App</p>
          <p class="text-gray-400">Identified and remediated Broken Access Controls, Stored XSS payloads, and SQL Injection bypass patterns. Enforced strict server-side authentication with Pydantic type casting and zero client-side trust assumptions.</p>

          <p class="text-white font-bold mt-2">Remediation Evidence:</p>
          <pre class="bg-black p-3 border border-emerald-500/20 text-emerald-400 rounded text-[11px] overflow-x-auto">[AUDIT] Payload Tested: ' OR 1=1 -- (BLOCKED by Pydantic)
          [AUDIT] Payload Tested: &lt;script&gt;alert(1)&lt;/script&gt; (SANITIZED)
          [STATUS] Server-side authorization rules enforced. Risk Score: 0/10</pre>
        `;
    }

    modal.classList.remove('hidden');
}

function closeReportModal() {
    const modal = document.getElementById('project-report-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// Global scope bindings for backward compatibility
if (typeof toggleProjectsSection !== "undefined") window.toggleProjectsSection = toggleProjectsSection;
if (typeof openImageLightbox !== "undefined") window.openImageLightbox = openImageLightbox;
if (typeof closeImageLightbox !== "undefined") window.closeImageLightbox = closeImageLightbox;
if (typeof prevLightboxImage !== "undefined") window.prevLightboxImage = prevLightboxImage;
if (typeof nextLightboxImage !== "undefined") window.nextLightboxImage = nextLightboxImage;

window.openReportModal = openReportModal;
window.closeReportModal = closeReportModal;