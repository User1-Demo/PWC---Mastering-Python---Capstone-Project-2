FROM python:3.11-slim AS base
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -e .

COPY src/ ./src/
COPY scripts/ ./scripts/
ENV PYTHONPATH=/app/src

RUN useradd -m appuser
USER appuser

EXPOSE 8000
CMD ["uvicorn", "cloudguard.main:app", "--host", "0.0.0.0", "--port", "8000"]