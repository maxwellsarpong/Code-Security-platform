FROM python:3.11-slim
WORKDIR /app

# Install system dependencies (build tools + git + curl for scanners)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc build-essential git curl nodejs npm \
    && ARCH=$(uname -m) \
    && if [ "$ARCH" = "x86_64" ]; then OSV_ARCH="linux_amd64"; else OSV_ARCH="linux_arm64"; fi \
    && curl -L "https://github.com/google/osv-scanner/releases/download/v1.9.1/osv-scanner_${OSV_ARCH}" -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner \
    && rm -rf /var/lib/apt/lists/*

# Explicitly set git path and configure for stability (fix RPC errors on large repos)
ENV GIT_PYTHON_GIT_EXECUTABLE=/usr/bin/git
RUN git config --global http.version HTTP/1.1 \
    && git config --global http.postBuffer 524288000

COPY requirements.txt ./
RUN python -m pip install --upgrade pip "setuptools<70"
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

#to be deleted on local run
COPY worker-entrypoint.sh ./worker-entrypoint.sh
RUN chmod +x ./worker-entrypoint.sh
ENV PYTHONPATH=/app/src
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
