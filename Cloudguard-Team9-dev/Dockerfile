FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY alembic.ini ./
COPY alembic ./alembic

RUN pip install --no-cache-dir .

RUN groupadd --system cloudguard \
    && useradd \
        --system \
        --gid cloudguard \
        --create-home \
        cloudguard \
    && chown -R cloudguard:cloudguard /app

USER cloudguard

EXPOSE 8000

CMD ["uvicorn", "cloudguard.main:app", "--host", "0.0.0.0", "--port", "8000"]