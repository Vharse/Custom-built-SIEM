from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.utils.signatures import SECURITY_SIGNATURES


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://kit.fontawesome.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "connect-src 'self' http://127.0.0.1:8000 http://localhost:8000 https://unpkg.com; "
            "font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com https://cdnjs.cloudflare.com;"
        )

        response.headers["Content-Security-Policy"] = csp_policy.strip()

        return response
