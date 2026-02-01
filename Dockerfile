FROM python:3.11-slim
WORKDIR /app

# Install system dependencies (build tools + git for repository cloning)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc build-essential git \
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
