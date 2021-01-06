FROM python:3.8-slim

COPY requirements.txt /
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r /requirements.txt \
    && apt-get purge -y --auto-remove gcc

COPY . .

ENTRYPOINT ["python", "/ssl_checker.py"]
