FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"
WORKDIR /app/backend
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 sentinel
COPY . .
RUN mkdir -p /app/backend/data && chown sentinel:sentinel /app/backend/data
USER sentinel
EXPOSE 8000
STOPSIGNAL SIGTERM
CMD ["python", "-m", "app.server"]

# Explicit development target; production does not install pytest/ruff.
FROM runtime AS development
USER root
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
USER sentinel
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--no-access-log", "--no-proxy-headers"]

FROM runtime AS production
