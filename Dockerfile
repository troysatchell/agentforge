# AgentForge web console — FastAPI mission-control surface.
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e '.[web]'

EXPOSE 8000
# Python launcher reads $PORT itself — no shell-expansion ambiguity.
CMD ["python", "-m", "agentforge.web"]
