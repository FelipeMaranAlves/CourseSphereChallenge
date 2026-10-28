FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    FLASK_DEBUG=false

WORKDIR /app

# Create non-root user for container hardening (Least Privilege)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /sbin/nologin appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/cornell-course-sphere-data && \
    chown -R appuser:appgroup /app

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "endpoints:app"]

