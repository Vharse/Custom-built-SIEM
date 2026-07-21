# SYSTRM INFORMATION & EVENT MANAGEMENT (SIEM)

An enterprise-grade personal portfolio and secure data ingress gateway. Built inside a containerized **Kali Linux** environment, the system utilizes a decoupled architecture: a hardened **FastAPI (Python)** backend kernel serving a framework-free, premium **Tailwind CSS** glassmorphism dashboard.

The entire architecture operates on **Zero-Trust principles** to mitigate vectors outlined in the **OWASP Top 10**.

---

## 🏗️ System Architecture

```text
       [ Client Browser Surface ]
        │                      │
   (Public Ingress)     (Privileged AJAX)
        │                      │
        ▼                      ▼
 [ Form Hardening ]     [ Vault Engine Framework ]
        │                      │   ├─ HttpOnly Token Check
        │                      │   ├─ Anti-CSRF Handshake Validation
        │                      │   └─ X-API-Key Header Match
        ▼                      ▼
┌────────────────────────────────────────────────────────┐
│               FASTAPI KERNEL GATEWAY                   │
└────────────────────────────────────────────────────────┘
                           │
                 [ SQLAlchemy ORM Core ]
                           │
                           ▼
              [ SQLite Secure Database ]
              

## 🛠️ Feature Matrix

1. Administration Terminal

    Dynamic Metrics: State-driven data tables tracking inbound message counts and security exceptions.

    Packet Inspection Module: Interactive UI modal isolating dynamic data display from DOM nodes safely.

    Atomic Purge Routines: Single-click transactional records deletion without leaving dangling database references.

2. Client Ingress Subsystem

    Input Sanitization: Strict boundary validation that normalizes inbound text arrays before ingestion.

## 🛡️ Defensive Security Architecture
1. Broken Object Level Authorization (BOLA) Mitigation

    Cryptographic Identity: Secure user routing sessions managed via JWT (HS256 HMAC) strings.

    HttpOnly Enclaves: Session tokens are isolated from JavaScript execution ranges via HttpOnly, Secure, and SameSite flags, completely shutting down XSS token-scraping vectors.

2. Cross-Site Scripting (XSS) Defenses

    Context-Aware Encoding: Client-side conversion rules render injected scripts harmless:

JavaScript

escapeHTML: (str) => {
    if (!str) return "N/A";
    return String(str)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

    Rigid CSP: Explicit response headers restricting resource execution bounds to validated zones.

3. Anti-CSRF & Boundary Protections

    Dual-Token State Validation: Verifies that custom client headers (X-CSRF-Token) precisely match server-generated tokens before executing any backend state change.

    Perimeter API Key Verification: Admin routes utilize absolute header alias matching (X-API-Key) pointing to high-entropy variables inside hidden server environments.

4. Adaptive Rate-Limiting & Forensic Logs

    Exponential Lockout Cooldown: Triggers a 60-second restriction after 3 sequential login failures, compounding by an additional 300 seconds for successive failures to stop brute-force vectors.

    Immutable Audit Trail: Forensic tracking logs containing client IP, target endpoints, timestamps, and failed payloads are committed to disk on suspicious behaviors.

## 💻 Tech Stack Blueprint

    Backend Core: Python, FastAPI, Uvicorn, SQLAlchemy ORM, Slowapi

    Frontend Surface: Vanilla ES6+, Tailwind CSS (Custom Dark/Glassmorphism Theme)

    Target Environment: Kali Linux OS, Docker, Docker Compose

## 🚀 Quickstart & Deployment
1. Configure Local Environment

Create your .env file inside the backend root directory:
Bash

cat << EOF > backend/.env
APP_ENV=development
ADMIN_USERNAME=sketra
ADMIN_PASSWORD=your_highly_secure_password_string
VAULT_API_KEY=SKEPTRA_SECURE_KEY_0000
EOF

2. Spin Up Orchestration Stack

Clear system volumes and trigger a clean container build:
Bash

docker compose down --volumes --remove-orphans
docker compose up -d --build --force-recreate

3. Stream Live Monitor Logs
Bash

docker compose logs -f backend

## 📊 Security Verification

Test the perimeter authorization barriers outside of the browser using your Kali terminal:
Bash

curl -X POST "[http://000.0.0.0:8000/api/manage/delete/1](http://000.0.0.0:8000/api/manage/delete/1)" \
     -H "X-API-Key: SKEPTRA_SECURE_KEY_0000" \
     -H "Content-Type: application/json"

Maintained under a hardened development workspace framework.