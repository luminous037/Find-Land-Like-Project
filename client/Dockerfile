FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

# gcc: 컴파일러
# tcpdump: 진단 및 패킷 캡처 도구
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    tcpdump && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "server.py"]
# 또는 CMD ["python", "client.py"]