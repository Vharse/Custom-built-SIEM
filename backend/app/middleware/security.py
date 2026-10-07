from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.utils.signatures import SECURITY_SIGNATURES


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        response = await call_next(request)

        # Original headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        # Additional security headers
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        response.headers["X-XSS-Protection"] = "0"

        # Content Security Policy
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com https://unpkg.com https://kit.fontawesome.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "connect-src 'self' http://127.0.0.1:8000 http://localhost:8000 https://unpkg.com; "
            "font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )

        response.headers["Content-Security-Policy"] = csp_policy.strip()

        return response