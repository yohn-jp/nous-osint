FROM docker.io/library/python:3.12-slim
WORKDIR /app
COPY pyproject.toml /app/
COPY src /app/src
RUN pip install --no-cache-dir .
COPY alembic.ini /app/
COPY migrations /app/migrations
COPY sources /app/sources
USER 10001:10001
CMD ["uvicorn", "nous.api:app", "--host", "0.0.0.0", "--port", "8000"]
