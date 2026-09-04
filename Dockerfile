# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/app/data \
    DECRYPTION_SCRIPTS_DIR=/opt/DECRYPTION_SCRIPTS

ARG DECRYPTION_SCRIPTS_REPO=https://github.com/ENIGMATIC-MAN/DECRYPTION_SCRIPTS.git
ARG DECRYPTION_SCRIPTS_REF=main

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch ${DECRYPTION_SCRIPTS_REF} ${DECRYPTION_SCRIPTS_REPO} ${DECRYPTION_SCRIPTS_DIR}

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mainbot.py /app/mainbot.py

RUN mkdir -p /app/data
CMD ["python", "/app/mainbot.py"]
