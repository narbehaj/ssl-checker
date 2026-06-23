FROM python:3.13-slim

WORKDIR /app

# Run as a normal user, not root.
RUN useradd --create-home checker

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ssl_checker.py socks.py ./

USER checker

ENTRYPOINT ["python", "/app/ssl_checker.py"]
