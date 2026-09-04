FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/ENIGMATIC-MAN/DECRYPTION_SCRIPTS /opt/DECRYPTION_SCRIPTS
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mainbot.py .
CMD ["python","mainbot.py"]
