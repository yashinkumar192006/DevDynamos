FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build tools for wheels that lack prebuilt binaries; libpq for asyncpg/psycopg.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies (layer cached on requirements.txt changes).
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Presidio's optional NLP signal; the app degrades gracefully if this fails,
# but shipping it keeps classification behavior consistent with development.
RUN python -m spacy download en_core_web_sm

# Application code.
COPY . .

# Startup helper (wait for DB → migrate → optional seed → exec server).
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    useradd --create-home --uid 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
