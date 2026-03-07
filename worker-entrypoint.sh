#!/bin/sh
# Worker entrypoint — handles both plain redis:// and TLS rediss:// URLs on Render
set -e

export PYTHONPATH=/app/src

echo "---------------------------------------------------------------"
echo "Security Compliance Platform Worker Startup"
echo "Timestamp: $(date)"
echo "---------------------------------------------------------------"

if [ -z "$REDIS_URL" ]; then
    echo "ERROR: REDIS_URL is not set! Worker will likely fail or default to localhost."
else
    # Extract only the scheme and host for safety
    SCHEME_HOST=$(echo "$REDIS_URL" | awk -F'@' '{print $2}' | cut -d/ -f1)
    if [ -z "$SCHEME_HOST" ]; then
        # Handle case without auth
        SCHEME_HOST=$(echo "$REDIS_URL" | cut -d/ -f3)
    fi
    echo "REDIS_URL detected. Scheme: $(echo $REDIS_URL | cut -d: -f1), Host: $SCHEME_HOST"
fi

echo "DATABASE_URL set: $([ -n "$DATABASE_URL" ] && echo yes || echo no)"
echo "PYTHONPATH set to: $PYTHONPATH"
echo "---------------------------------------------------------------"

# Using our custom worker entrypoint which handles TLS correctly
exec python -m app.worker
