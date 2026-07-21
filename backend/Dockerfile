FROM node:22-bookworm-slim AS frontend-builder
WORKDIR /siem-tool

COPY package*.json ./
RUN npm ci

COPY frontend/ ./frontend/

RUN npx tailwindcss -i ./frontend/resources/css/input.css -o ./frontend/resources/css/output.css --minify

FROM python@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0 AS backend-builder
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /siem-tool

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /siem-tool/backend/.venv
ENV PATH="/siem-tool/backend/.venv/bin:$PATH"

COPY backend/requirements.txt ./backend/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r backend/requirements.txt

FROM python@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /siem-tool/backend

COPY --from=backend-builder /siem-tool/backend/.venv /siem-tool/backend/.venv

COPY backend/ /siem-tool/backend/

COPY alembic/ /siem-tool/alembic/
COPY alembic.ini* /siem-tool/

COPY --from=frontend-builder /siem-tool/frontend/ /siem-tool/frontend/

# --- FIX: Create the directory during build so it exists in read-only mode ---
RUN mkdir -p /siem-tool/backend/frontend
# ----------------------------------------------------------------------------

ENV PATH="/siem-tool/backend/.venv/bin:$PATH"
ENV PYTHONPATH=/siem-tool:/siem-tool/backend

# Ensure logix_user owns the directory
RUN useradd -m logix_user && chown -R logix_user:logix_user /siem-tool
USER logix_user

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]