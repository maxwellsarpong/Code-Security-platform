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

<img src="Secure-Code-Platform.drawio.svg" alt="Architecture Diagram" width="800" />

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

### Authentication & Multi-tenancy

The platform supports multi-tenancy via **JWT Authentication** (for users) and **API Keys** (for automated services).

#### 1. Register & Login (JWT)

First, register a new user. This will automatically create a new tenant for you.

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "yourpassword",
       "tenant_name": "Acme Corp"
     }'
```

Then, login to receive your access token (JSON supported):

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "yourpassword"
     }'
```

Response: `{ "access_token": "...", "token_type": "bearer" }`

Use the `access_token` in the `Authorization: Bearer <token>` header for subsequent requests.

#### 2. API Key Authentication (Fallback)

For automated services, use `/token` with form-data (standard OAuth2) or an API key:

```bash
# OAuth2 Token endpoint (form-data)
curl -X POST http://localhost:8000/api/v1/auth/token \
     -d "username=user@example.com&password=yourpassword"
```

Use the `api_key` in the `x-api-key: <api_key>` header.

---

### API Reference

#### Authentication
- `POST /api/v1/auth/register`: Register user & tenant.
- `POST /api/v1/auth/login`: Login to get JWT (JSON).
- `POST /api/v1/auth/token`: OAuth2 legacy login (Form-data).

#### Scans
- `POST /api/v1/scans`: Start a new security scan.
  ```bash
  curl -X POST http://localhost:8000/api/v1/scans \
       -H "Authorization: Bearer <JWT_TOKEN>" \
       -H "Content-Type: application/json" \
       -d '{ "repo_url": "https://github.com/owner/repo" }'
  ```
- `GET /api/v1/scans`: List all scans for the tenant.
- `GET /api/v1/scans/{scan_id}`: Get details of a specific scan.

#### Findings & Resolution
- `GET /api/v1/findings/fixed`: List all successfully resolved vulnerabilities.
- `POST /api/v1/findings/{target_id}/resolve`: Resolve vulnerabilities. Accepts either a **Finding ID** (to fix one) or a **Scan ID** (to fix all in that scan).
  ```bash
  curl -X POST http://localhost:8000/api/v1/findings/<ID>/resolve \
       -H "Authorization: Bearer <JWT_TOKEN>" \
       -H "Content-Type: application/json" \
       -d '{ "github_token": "your_personal_access_token_if_not_in_settings" }'
  ```

#### Tenants & Usage
- `GET /api/v1/tenants`: List all tenants in the system.
- `POST /api/v1/tenants`: Create a tenant and API key (Scaffold).
- `GET /api/v1/tenants/{tenant_id}/usage`: Retrieve usage stats for a tenant.
- `POST /api/v1/tenants/subscription/renew`: Manually renew the monthly quota subscription for the current tenant.
  ```bash
  curl -X POST http://localhost:8000/api/v1/tenants/subscription/renew?amount=100.0 \
       -H "x-api-key: <YOUR_API_KEY>"
  ```

---

## Running the worker (queue mode)

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

## Observability (Prometheus + Sentry) 📈

- API metrics: `GET /api/v1/metrics` (Prometheus format)
- Worker metrics: exposed on `9100` by default when running the worker
- Sentry: set `SENTRY_DSN` to enable error reporting from API & worker

Example (local):
```bash
# run everything with docker-compose
SENTRY_DSN="" docker compose up --build
# scrape metrics from http://localhost:8000/metrics and http://localhost:9100/
```

## CI / running without Redis

- The scaffold supports a synchronous fallback for local dev and CI. Set `WORKER_SYNC=true` to run scan jobs synchronously (the default in tests/CI).