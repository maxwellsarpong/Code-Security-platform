# Security & Compliance Monitoring — Backend (FastAPI) 🛡

Minimal scaffold for the Security & Compliance Monitoring API (FastAPI).

What you get
- Runnable FastAPI app with a simple scan API (POST /api/v1/scans)
- **Real security scanners**: Bandit (Python static analysis), Checkov (IaC security), pip-audit (dependency vulnerabilities)
- SQLite default dev DB (configurable via DATABASE_URL)
- Dockerfile + docker-compose for local dev
- Unit test + GitHub Actions CI scaffold

## Security Scanners

The platform integrates four industry-standard security scanners:

1. **Semgrep** - Multi-language static analysis
   - Supports 18+ languages: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C/C++, C#, Rust, Kotlin, Scala, Swift
   - Uses Semgrep Registry community rules
   - OWASP Top 10 and CWE coverage

2. **Bandit** - Python static security analysis
   - Detects hard-coded secrets, SQL injection, shell injection, insecure crypto
   - 68+ built-in security checks
   - Severity-based risk scoring

2. **Checkov** - Infrastructure as Code security
   - Scans Terraform, Dockerfile, Kubernetes, CloudFormation
   - 1000+ built-in policies (CIS, PCI-DSS, HIPAA compliance)
   - Identifies misconfigurations before deployment

3. **pip-audit** - Python dependency vulnerability scanning
   - Checks for known CVEs in dependencies
   - Uses PyPI Advisory Database
   - Provides upgrade recommendations

### Scanner Workflow

1. Repository is cloned to temporary directory
2. All applicable scanners run in parallel
3. Findings are aggregated and stored in database
4. Risk score calculated based on severity (0-10 scale)
5. Temporary files cleaned up

Quickstart (macOS):

1) Create virtualenv and run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

2) With Docker Compose

```bash
docker compose up --build
# API -> http://localhost:8000
```

API (examples)

- Health: GET /health
- Start scan: POST /api/v1/scans  -> body: { "repo_url": "https://github.com/owner/repo" }
  - Clones repository and runs Semgrep (multi-language), Bandit, Checkov, and pip-audit scanners
  - Returns scan ID for polling
- Get scan: GET /api/v1/scans/{scan_id}
  - Returns scan status, risk score, and findings
  - Findings include: title, severity, description, remediation, file path, line number, CVE ID

Running the worker (queue mode)

- Local (dev):
```bash
# start a local redis (homebrew) or use docker-compose (recommended)
redis-server --port 6379 &
REDIS_URL=redis://localhost:6379 rq worker scans
# or use the convenience entrypoint
REDIS_URL=redis://localhost:6379 python -m app.worker
```

- With Docker Compose (recommended):
```bash
docker compose up --build
# api -> http://localhost:8000
# worker logs are visible in the `worker` service
```

Observability (Prometheus + Sentry) 📈

- API metrics: `GET /metrics` (Prometheus format)
- Worker metrics: exposed on `9100` by default when running the worker
- Sentry: set `SENTRY_DSN` to enable error reporting from API & worker

Example (local):
```bash
# run everything with docker-compose
SENTRY_DSN="" docker compose up --build
# scrape metrics from http://localhost:8000/metrics and http://localhost:9100/
```

Tenants, API keys, quotas & billing (scaffold) 💳

- Create a tenant + API key (scaffold):

  ```
  POST /api/v1/tenants?name=acme&rate_limit_per_minute=10&quota_per_month=100
  ```

  Response: `{ "tenant_id": "...", "api_key": "..." }`

- Use the API key: include header `x-api-key: <api_key>` on requests. The server enforces per-tenant rate limits and monthly quotas.

- Billing & metering: each completed scan records a `Usage` row and a `BillingEvent`. Retrieve per-tenant usage with:

  ```
  GET /api/v1/tenants/{tenant_id}/usage
  ```

CI / running without Redis

- The scaffold supports a synchronous fallback for local dev and CI. Set `WORKER_SYNC=true` to run scan jobs synchronously (the default in tests/CI).