FROM docker.io/library/python@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b
WORKDIR /app
COPY pyproject.toml /app/
COPY src /app/src
RUN pip install --no-cache-dir .
COPY alembic.ini /app/
COPY migrations /app/migrations
COPY sources /app/sources
USER 10001:10001
CMD ["uvicorn", "nous.api:app", "--host", "0.0.0.0", "--port", "8000"]
