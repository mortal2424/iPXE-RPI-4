FROM python:3.13-slim
WORKDIR /app
RUN apt-get -o Acquire::ForceIPv4=true update \
    && apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends snmp \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paramiko==4.0.0
COPY panel.py boot-http.py telemetry.py poe.py reinstall.py ./
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python3"]
