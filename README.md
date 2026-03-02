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

### Authentication

The platform supports **JWT Authentication** (via login) and **API Key Authentication** (for automated services).

#### 1. Register & Login (JWT)

```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{ "email": "user@example.com", "password": "yourpassword" }'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{ "email": "user@example.com", "password": "yourpassword" }'
# Response: { "access_token": "...", "token_type": "bearer" }
```

Use the `access_token` in the `Authorization: Bearer <token>` header for all subsequent requests.

#### 2. API Key Authentication

Generate an API key after logging in (`POST /api/v1/user/api-key`), then use it via the `x-api-key` header:

```bash
curl http://localhost:8000/api/v1/scans \
     -H "x-api-key: <YOUR_API_KEY>"
```

---

### Plans & Quotas

Every user is assigned a plan that controls their monthly scan and resolution limits.

| Plan | Monthly Scans | Monthly Resolves |
|---|---|---|
| `free` | 2 | 2 |
| `team` | 500 | 500 |
| `enterprise` | 2000 | 2000 |

- New users are automatically placed on the **Free** plan.
- Check your current plan and quotas at `GET /api/v1/user/profile`.
- Check current-month usage at `GET /api/v1/user/usage`.
- When a quota is exceeded the API returns `403` with a descriptive message indicating which quota was hit and that an upgrade is required.
- **Upgrade/Transition Plans**:
  - `POST /api/v1/user/subscription/team`: Move to the **Team** tier.
  - `POST /api/v1/user/subscription/enterprise`: Move to the **Enterprise** tier.
- Renew / reset your current monthly quotas with `POST /api/v1/user/subscription/renew`.

---

### API Reference

All protected endpoints accept either `Authorization: Bearer <JWT_TOKEN>` or `x-api-key: <API_KEY>`.

#### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | Register a new user account |
| `POST` | `/api/v1/auth/init-superuser` | Bootstraps the system by creating the first superuser. Returns `403` if a superuser already exists. |
| `POST` | `/api/v1/auth/login` | JSON login — returns a JWT. Returns `404` if the email is not found, `401` for a wrong password |
| `POST` | `/api/v1/auth/token` | OAuth2 form-data login — returns a JWT |

```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{ "email": "user@example.com", "password": "yourpassword" }'

# Create Initial Superuser (Run only once to bootstrap)
curl -X POST http://localhost:8000/api/v1/auth/init-superuser \
     -H "Content-Type: application/json" \
     -d '{ "email": "admin@example.com", "password": "secureadminpassword" }'

# Login (JSON)
curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{ "email": "user@example.com", "password": "yourpassword" }'
# Response: { "access_token": "...", "token_type": "bearer" }
```

---

#### User

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `GET` | `/api/v1/user/profile` | ✅ | Get profile and quota info for the authenticated user |
| `PUT` | `/api/v1/user/profile` | ✅ | Update optional attributes (like `slack_webhook_url` or `github_token`) |
| `GET` | `/api/v1/user/usage` | ✅ | Get usage history and current-month credit summary |
| `POST` | `/api/v1/user/api-key` | ✅ | Generate a new API key for the authenticated user |
| `POST` | `/api/v1/user/subscription/team` | ✅ | Upgrade user to the Team Tier |
| `POST` | `/api/v1/user/subscription/enterprise` | ✅ | Upgrade user to the Enterprise Tier |
| `POST` | `/api/v1/user/subscription/renew` | ✅ | Renew current monthly quota (optionally pass `?amount=100.0`) |

```bash
# Update user profile
curl -X PUT http://localhost:8000/api/v1/user/profile \
     -H "Authorization: Bearer <JWT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{ "slack_webhook_url": "https://hooks.slack.com/services/...", "github_token": "ghp_..." }'

# Get usage
curl http://localhost:8000/api/v1/user/usage \
     -H "Authorization: Bearer <JWT_TOKEN>"

# Renew quota
curl -X POST "http://localhost:8000/api/v1/user/subscription/renew?amount=100.0" \
     -H "Authorization: Bearer <JWT_TOKEN>"

# Upgrade to Team Plan
curl -X POST http://localhost:8000/api/v1/user/subscription/team \
     -H "Authorization: Bearer <JWT_TOKEN>"
```

---

#### Admin

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `GET` | `/api/v1/admin/users` | ✅ (superuser) | List all registered users |
| `PUT` | `/api/v1/admin/users/{user_id}` | ✅ (superuser) | Update a user's plan, quota, or `is_superuser` status |

```bash
# List users
curl http://localhost:8000/api/v1/admin/users \
     -H "Authorization: Bearer <SUPERUSER_JWT>"

# Promote user to enterprise
curl -X PUT http://localhost:8000/api/v1/admin/users/<USER_ID> \
     -H "Authorization: Bearer <SUPERUSER_JWT>" \
     -H "Content-Type: application/json" \
     -d '{ "plan": "enterprise" }'
```

---


#### Scans

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `POST` | `/api/v1/scans` | ✅ (quota enforced) | Start a new security scan |
| `GET` | `/api/v1/scans` | ✅ | List all scans for the authenticated user |
| `GET` | `/api/v1/scans/{scan_id}` | ✅ | Get details of a specific scan |

```bash
# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
     -H "Authorization: Bearer <JWT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{ "repo_url": "https://github.com/owner/repo" }'
```

---

#### Findings & Resolution

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `GET` | `/api/v1/findings/fixed` | ✅ | List all successfully resolved vulnerabilities |
| `POST` | `/api/v1/findings/{target_id}/resolve` | ✅ (quota enforced) | Resolve a finding or all findings in a scan |

Pass a **Finding ID** to fix one vulnerability or a **Scan ID** to fix all findings in that scan.  
Add `?force_sync=true` to wait for the result synchronously.

```bash
curl -X POST "http://localhost:8000/api/v1/findings/<ID>/resolve?force_sync=true" \
     -H "Authorization: Bearer <JWT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{ "github_token": "your_personal_access_token" }'
```

---

#### Observability

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/metrics` | Prometheus metrics (CPU, request counts, latencies, etc.) |

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