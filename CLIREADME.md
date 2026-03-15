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



The platform includes a powerful CLI script to trigger scans and resolutions directly from your terminal.

#### 1. Installation
Ensure you have the dependencies installed:
```bash
pip install typer[all] rich requests
```

#### 2. Usage
[Get your API key from the dashboard](https://code-security-platform-frontend-lan.vercel.app/login)

Running the CLI tool

```bash
# Showing the help menu
scp-cli --help

# Authenticate (Set your API key)
scp-cli auth --key <YOUR_API_KEY>

# Start a scan
scp-cli scan https://github.com/owner/repo

# Check scan status
scp-cli status <scan_id>

# Resolve findings (Bulk fix for a scan)
scp-cli resolve <scan_id>

# Check all successfully resolved findings
scp-cli resolved

# Get the PR URL for a specific resolved finding
scp-cli pr <finding_id>

# Check your quota
scp-cli usage
```