FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONPATH=/app
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
EXPOSE 8501
CMD ["streamlit", "run", "apps/dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
