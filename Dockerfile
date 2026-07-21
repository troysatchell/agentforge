# AgentForge web console — FastAPI mission-control surface.
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e '.[web]'

EXPOSE 8000
# Railway injects $PORT; default to 8000 for local `docker run`.
CMD ["sh", "-c", "uvicorn agentforge.web.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
