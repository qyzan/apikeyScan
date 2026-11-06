FROM python:3.10-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY core/ core/
COPY scanners/ scanners/
COPY apiKeyScan.py .

RUN pip install --no-cache-dir --no-deps . && \
    pip install --no-cache-dir aiohttp colorama pyyaml boto3 cryptography

RUN useradd --create-home --uid 1000 apikeyscan && \
    mkdir -p /app/reports && chown apikeyscan:apikeyscan /app/reports

USER apikeyscan

ENTRYPOINT ["apikeyscan"]
