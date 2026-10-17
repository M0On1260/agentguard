FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt requirements-agent.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-agent.txt
COPY . .
ENV AGENTGUARD_DB=/data/audit.db
RUN mkdir -p /data
EXPOSE 8000
CMD ["uvicorn", "gateway.api:app", "--host", "0.0.0.0", "--port", "8000"]
