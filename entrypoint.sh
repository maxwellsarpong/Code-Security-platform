#!/bin/sh
set -e

# MAGIC STRING for log verification
echo "!!! ENTRYPOINT EXECUTING !!!"

echo "==============================================================="
echo "ENTRYPOINT DIAGNOSTICS"
echo "Date:         $(date)"
echo "Current Dir:  $(pwd)"
echo "Service Type: '$SERVICE_TYPE'"
echo "Internal Port: '$PORT' (Render port if set)"
echo "PYTHONPATH:   '$PYTHONPATH'"
echo "==============================================================="

# Trap termination signals to log them
trap 'echo "!!! RECEIVED SIGTERM/SIGINT - SHUTTING DOWN !!!"; exit 0' TERM INT

if [ "$SERVICE_TYPE" = "worker" ]; then
    echo ">>> ROBUST MATCH: Decided to start WORKER service."
    exec /app/worker-entrypoint.sh
elif [ "$SERVICE_TYPE" = "api" ]; then
    echo ">>> ROBUST MATCH: Decided to start API service."
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000
else
    echo ">>> NO MATCH: SERVICE_TYPE is missing or invalid (current: '$SERVICE_TYPE')."
    echo ">>> DEFAULTING TO API FOR SAFETY."
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000
fi
