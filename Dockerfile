FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/app/data
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY mainbot.py ./mainbot.py
COPY migrations ./migrations
COPY tests ./tests
COPY README.md CHANGELOG.md ./
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import os,sqlite3; p=os.getenv('DATA_DIR','/app/data')+'/prodecryptor.db'; sqlite3.connect(p).execute('PRAGMA quick_check').fetchone() if os.path.exists(p) else exit(0)"
CMD ["python","mainbot.py"]
