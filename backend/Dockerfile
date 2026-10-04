FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    AUDIT_DB=/data/audits.db \
    STATIC_DIR=/app/frontend_dist

WORKDIR /app

COPY app/ ./app/

RUN mkdir -p /data && useradd -r -u 10001 appuser \
    && chown -R appuser /data /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=20 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status == 200 else 1)"

CMD ["python3", "-m", "app.server"]
