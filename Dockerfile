# Attest API + cron image. Single image used for the web (private) service and
# the seal-and-anchor cron job on Render.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App source.
COPY . .

# Default port; Render injects $PORT at runtime.
EXPOSE 8000

CMD ["sh", "scripts/start.sh"]
