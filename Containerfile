ARG PYTHON_BASE=docker.io/library/python@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b

FROM docker.io/library/node:24-bookworm-slim@sha256:a43f7fc3e52e87d12a905f46eea0275def84ca8f2981a5b53fed44d7fb398ee0 AS ui-build
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
COPY ui/index.html ui/quasar.config.ts ui/tsconfig.json ./
COPY ui/src ./src
RUN npm ci --no-audit --no-fund
RUN npm run typecheck && npm run build

FROM ${PYTHON_BASE}
WORKDIR /app
ENV NOUS_REPORTS_DIR=/app/reports
COPY pyproject.toml /app/
COPY src /app/src
USER 0:0
RUN pip install --no-cache-dir .
COPY alembic.ini /app/
COPY migrations /app/migrations
COPY sources /app/sources
# Report administration runs in this image as well as the dedicated Worker.
# Installed Python packages live under site-packages, not the source checkout.
COPY reports/templates /app/reports/templates
RUN python -c 'from nous.report_templates import load_templates; assert set(load_templates()) == {"security-daily", "cve-kev-deep-dive"}'
COPY --from=ui-build /ui/dist/spa /app/ui
USER 10001:10001
CMD ["uvicorn", "nous.api:app", "--host", "0.0.0.0", "--port", "8000"]
