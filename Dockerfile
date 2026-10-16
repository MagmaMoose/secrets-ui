# secrets-ui: the FastAPI backend serving the built React frontend, as one image.

# The frontend is static files, the same on every architecture, so it builds once on the
# build host rather than under emulation for each target.
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS backend
RUN pip install --no-cache-dir uv==0.11.19
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# The locked dependencies and the package itself, no dev group, into /app/.venv.
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ARG VERSION=dev
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_VERSION=${VERSION} \
    SECRETS_UI_STATIC_DIR=/app/static \
    PORT=8080

COPY --from=backend /app/.venv /app/.venv
COPY --from=frontend /frontend/dist /app/static

# Numeric and above 10000, so a pod's runAsUser can match the image exactly.
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["python", "-m", "secrets_ui"]
