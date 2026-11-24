FROM python:3.12-slim

WORKDIR /srv/app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY eval/ ./eval/

RUN useradd --create-home --shell /usr/sbin/nologin appuser && chown -R appuser:appuser /srv/app
USER appuser

EXPOSE 8080

CMD ["adk", "api_server", "--host", "0.0.0.0", "--port", "8080", "."]
