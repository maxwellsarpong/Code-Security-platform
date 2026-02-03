FROM python:3.11-slim
WORKDIR /app

# Install system dependencies (build tools + git + curl for scanners)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc build-essential git curl \
    && curl -L https://github.com/google/osv-scanner/releases/download/v1.9.1/osv-scanner_linux_arm64 -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner \
    && rm -rf /var/lib/apt/lists/*

# Explicitly set git path for GitPython
ENV GIT_PYTHON_GIT_EXECUTABLE=/usr/bin/git

COPY requirements.txt ./
RUN python -m pip install --upgrade pip setuptools
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
ENV PYTHONPATH=/app/src
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
