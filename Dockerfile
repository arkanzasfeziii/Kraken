FROM python:3.12-slim

LABEL maintainer="arkanzasfeziii"
LABEL description="Kraken — Kubernetes & Cloud Native Offensive Suite"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY kraken/ kraken/

ENTRYPOINT ["python", "-m", "kraken"]
CMD ["--help"]
