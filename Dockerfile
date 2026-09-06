# Single-image deploy (Railway / HuggingFace Spaces / any Docker host).
# Serves UI + API on $PORT.
FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY frontend_dist ./frontend_dist
COPY templates ./templates

CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
