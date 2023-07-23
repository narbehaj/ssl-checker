FROM python:3.8-alpine AS builder

WORKDIR /app
COPY requirements.txt .

RUN apk add --no-cache gcc musl-dev libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del gcc musl-dev libffi-dev

FROM python:3.8-alpine

COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . .

ENTRYPOINT ["python", "/ssl_checker.py"]
