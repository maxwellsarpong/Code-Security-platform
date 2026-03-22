import typer
import requests
import json
import os
import time
import tempfile
import zipfile
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
import shutil
from typing import Optional
from uuid import UUID

from app import __version__

app = typer.Typer(
    help="Security Compliance Platform CLI - Secure your code from the terminal.",
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]}
)
console = Console()

def version_callback(value: bool):
    if value:
        console.print(f"scp-cli version: [bold cyan]{__version__}[/bold cyan]")
        raise typer.Exit()

CONFIG_DIR = Path.home() / ".scp"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_API_URL = "https://code-security-platform.onrender.com"

def save_config(api_key: str, api_url: str = DEFAULT_API_URL):
    CONFIG_DIR.mkdir(exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump({"api_key": api_key, "api_url": api_url}, f)

def load_config():
    if not CONFIG_FILE.exists():
        return None
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def get_headers():
    config = load_config()
    if not config:
        console.print("[bold red]Error:[/bold red] Not authenticated. Run `scp-cli auth --key <your-api-key>` first.")
        raise typer.Exit(code=1)
    return {"x-api-key": config["api_key"]}

def get_url(endpoint: str):
    config = load_config()
    base_url = config["api_url"] if config else DEFAULT_API_URL
    return f"{base_url.rstrip('/')}/api/v1{endpoint}"

def _zip_directory(path: Path, zip_handle: zipfile.ZipFile):
    """Recursively zip a path (file or directory)."""
    if path.is_file():
        zip_handle.write(path, path.name)
        return

    exclude_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".scp"}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            file_path = Path(root) / file
            arcname = file_path.relative_to(path)
            zip_handle.write(file_path, arcname)

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show the version and exit.", hidden=True
    ),
):
    """
    Security Compliance Platform CLI
    """
    pass

@app.command()
def version():
    """Display the current version of scp-cli."""
    console.print(f"scp-cli version: [bold cyan]{__version__}[/bold cyan]")

@app.command()
def auth(
    key: str = typer.Option(..., help="Your SC-Platform API Key"),
    url: str = typer.Option(DEFAULT_API_URL, help="Override default API URL")
):
    """Authenticate the CLI with your API Key."""
    save_config(key, url)
    console.print(Panel(f"[bold green]Success![/bold green] Authenticated with {url}", title="Authentication"))

@app.command()
def scan(
    repo_url: str = typer.Argument(..., help="URL of the repository OR local directory path (e.g. '.')"),
    token: Optional[str] = typer.Option(None, help="GitHub/GitLab Personal Access Token for private repos")
):
    """Trigger a new security scan for a repository or local workspace."""
    headers = get_headers()
    local_path = Path(repo_url).expanduser().resolve()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        try:
            # Check if the input is a local file or directory
            if local_path.exists():
                progress.add_task(description=f"Preparing local scan for {local_path.name}...", total=None)
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    tmp_path = Path(tmp.name)
                    with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                        _zip_directory(local_path, zf)
                
                progress.add_task(description="Uploading workspace for scan...", total=None)
                url = get_url("/scans/local")
                try:
                    with open(tmp_path, "rb") as f:
                        files = {"file": (f"{local_path.name}.zip", f, "application/zip")}
                        response = requests.post(url, files=files, headers=headers)
                        if response.status_code == 403:
                            console.print("[bold red]Error:[/bold red] Free trial limit exceeded. Please upgrade to a paid plan.")
                            raise typer.Exit(code=1)
                        response.raise_for_status()
                        data = response.json()
                finally:
                    if tmp_path.exists():
                        tmp_path.unlink()
                
                label = f"Local: {local_path}"
            else:
                # Assume it's a remote URL
                progress.add_task(description="Triggering remote scan...", total=None)
                url = get_url("/scans")
                payload = {"repo_url": repo_url}
                if token:
                    payload["github_token"] = token
                response = requests.post(url, json=payload, headers=headers)
                if response.status_code == 403:
                    console.print("[bold red]Error:[/bold red] Free trial limit exceeded. Please upgrade to a paid plan.")
                    raise typer.Exit(code=1)
                response.raise_for_status()
                data = response.json()
                label = repo_url

            console.print(Panel(
                f"[bold cyan]Scan ID:[/bold cyan] {data['id']}\n"
                f"[bold cyan]Status:[/bold cyan] {data['status']}\n"
                f"[bold cyan]Target:[/bold cyan] {label}",
                title="Scan Triggered"
            ))
            console.print("\nUse `scp-cli status " + data['id'] + "` to check progress.")
            
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def status(
    scan_id: str = typer.Argument(..., help="The UUID of the scan")
):
    """Check the status and results of a scan."""
    url = get_url(f"/scans/{scan_id}")
    headers = get_headers()

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        table = Table(title=f"Scan Status: {data['status']}")
        table.add_column("Scanner", style="magenta")
        table.add_column("Findings", style="red")
        table.add_column("Severity Breakdown", style="yellow")

        findings = data.get("findings", [])
        if not findings:
            console.print(Panel(f"Status: [bold green]{data['status']}[/bold green]\nNo findings detected yet.", title=f"Scan {scan_id}"))
        else:
            # Group findings by scanner
            scanner_stats = {}
            for f in findings:
                s = f["scanner_name"]
                scanner_stats[s] = scanner_stats.get(s, 0) + 1
            
            for scanner, count in scanner_stats.items():
                table.add_row(scanner, str(count), "N/A")
            
            console.print(table)
            console.print(f"\n[dim]Total findings to date: {len(findings)}[/dim]")
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def findings(
    scan_id: str = typer.Argument(..., help="The UUID of the scan")
):
    """List detailed security issues for a specific scan."""
    url = get_url(f"/scans/{scan_id}")
    headers = get_headers()

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        findings_list = data.get("findings", [])
        if not findings_list:
            console.print(Panel(f"Scan Status: [bold green]{data['status']}[/bold green]\nNo findings detected yet.", title=f"Scan {scan_id}"))
        else:
            table = Table(title=f"Findings for Scan: {scan_id}")
            table.add_column("ID", style="cyan")
            table.add_column("Severity", style="red")
            table.add_column("File Path", style="yellow")
            table.add_column("Status", style="green")

            for f in findings_list:
                status_str = "[green][bold]Fixed[/bold][/green]" if f["is_fixed"] else "[yellow]Open[/yellow]"
                table.add_row(
                    f["id"],
                    f.get("severity", "N/A"),
                    f"{f.get('file_path', 'N/A')}:{f.get('line_number', '')}" if f.get("line_number") else f.get("file_path", "N/A"),
                    status_str
                )
            
            console.print(table)
            console.print(f"\n[dim]Total findings in this scan: {len(findings_list)}[/dim]")
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def resolve(
    target_id: str = typer.Argument(..., help="Finding ID or Scan ID to resolve"),
    token: Optional[str] = typer.Option(None, help="GitHub token (if not saved in profile)")
):
    """Trigger automated resolution for a finding or an entire scan."""
    headers = get_headers()
    
    # 1. Determine if it's a local scan to request sync resolution
    is_local_scan = False
    try:
        check_url = get_url(f"/scans/{target_id}")
        check_resp = requests.get(check_url, headers=headers)
        if check_resp.status_code == 200:
            is_local_scan = check_resp.json().get("is_local", False)
        elif check_resp.status_code == 404:
            # Maybe it's a Finding ID. Check the finding's parent scan.
            finding_url = get_url(f"/findings/{target_id}")
            finding_resp = requests.get(finding_url, headers=headers)
            if finding_resp.status_code == 200:
                scan_id = finding_resp.json().get("scan_id")
                scan_resp = requests.get(get_url(f"/scans/{scan_id}"), headers=headers)
                if scan_resp.status_code == 200:
                    is_local_scan = scan_resp.json().get("is_local", False)
    except:
        pass

    url = get_url(f"/findings/{target_id}/resolve")
    payload = {}
    if token:
        payload["github_token"] = token
    
    # Always request synchronous resolution from the CLI for immediate feedback
    params = {"force_sync": "true"}

    data = None
    with Progress(SpinnerColumn(), transient=True) as progress:
        description = "Processing resolution..."
        if is_local_scan:
            description = "Generating local fixes (this may take a minute)..."
        else:
            description = "Generating fixes and creating Pull Request..."
        
        progress.add_task(description=description, total=None)
        try:
            # Increase timeout to 180s to allow for AI generation + Git operations
            response = requests.post(url, json=payload, headers=headers, params=params, timeout=180)
            if response.status_code != 200:
                try:
                    detail = response.json().get('detail', 'Unknown error')
                except:
                    detail = response.text
                console.print(f"[bold red]Failed:[/bold red] {detail}")
                return
            data = response.json()
        except requests.exceptions.Timeout:
            console.print("[bold red]Error:[/bold red] The request timed out. The resolution might still be running in the background.")
            console.print("[dim]You can check the status later using 'scp-cli status' or 'scp-cli pr'.[/dim]")
            return
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            return

    if data:
        pr_url = data.get("pr_url")
        message = data.get("message")
        
        output_content = f"[bold green]Status:[/bold green] {data.get('status', 'success')}\n"
        output_content += f"[bold white]Message:[/bold white] {message}"
        
        if pr_url and pr_url != "local-fix-applied":
            output_content += f"\n[bold cyan]Pull Request:[/bold cyan] [link={pr_url}]{pr_url}[/link]"

        console.print(Panel(
            output_content,
            title="Resolution Success"
        ))
        
        # Handle local fixes if present
        fixes = data.get("fixes")
        if fixes:
            console.print(f"\n[bold cyan]Detected {len(fixes)} local workspace fixes.[/bold cyan]")
            if typer.confirm("Would you like to apply these fixes to your local workspace now?"):
                for fix in fixes:
                    file_path = fix["file_path"]
                    new_content = fix["new_content"]
                    
                    # Ensure path is relative to current directory for application
                    local_file = Path(file_path.lstrip("/"))
                    if local_file.exists():
                        backup = local_file.with_suffix(local_file.suffix + ".bak")
                        shutil.copy2(local_file, backup)
                        console.print(f"  [dim]Backup created: {backup.name}[/dim]")
                    
                    local_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(local_file, "w") as f:
                        f.write(new_content)
                    console.print(f"  [bold green]✓ Applied fix to {file_path}[/bold green]")
                
                console.print("\n[bold green]Workspace fixes applied successfully![/bold green]")
                console.print("[dim]Please review the changes and run your tests.[/dim]")

@app.command()
def resolved():
    """Check all successfully resolved findings."""
    url = get_url("/findings/fixed")
    headers = get_headers()

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        table = Table(title="Resolved Findings")
        table.add_column("ID", style="cyan")
        table.add_column("Scanner", style="magenta")
        table.add_column("Title", style="white")
        table.add_column("Severity", style="yellow")

        if not data:
            console.print(Panel("No resolved findings detected yet.", title="Resolved Findings"))
        else:
            for f in data:
                # Truncate ID for readability
                fid = str(f.get("id"))[:8] if f.get("id") else "N/A"
                table.add_row(fid, f.get("scanner_name", "N/A"), f.get("title", "N/A")[:50], f.get("severity", "N/A"))
            
            console.print(table)
            console.print(f"\n[dim]Total resolved findings: {len(data)}[/dim]")
            
    except Exception as e:
        if hasattr(e, "response") and e.response is not None:
            console.print(f"[bold red]Error:[/bold red] {e.response.text}")
        else:
            console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def pr(
    finding_id: str = typer.Argument(..., help="The UUID of the resolved finding")
):
    """Get the Pull Request URL for a resolved finding."""
    url = get_url(f"/findings/{finding_id}")
    headers = get_headers()

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 404:
            # Check if user accidentally passed a Scan ID
            scans_url = get_url(f"/scans/{finding_id}")
            scan_check = requests.get(scans_url, headers=headers)
            if scan_check.status_code == 200:
                console.print(Panel(
                    f"[bold yellow]Note:[/bold yellow] {finding_id} is a [bold cyan]Scan ID[/bold cyan].\n"
                    "The `pr` command requires a [bold magenta]Finding ID[/bold magenta].\n"
                    "Use `scp-cli status " + finding_id + "` to see the findings and their IDs.",
                    title="Incorrect ID Type"
                ))
            else:
                console.print(f"[bold red]Error:[/bold red] Finding '{finding_id}' not found.")
            return

        response.raise_for_status()
        data = response.json()

        if not data.get("is_fixed"):
            console.print(Panel(f"[bold yellow]Finding {finding_id} is not marked as resolved yet.[/bold yellow]", title="Status"))
            return

        pr_url = data.get("pr_url")
        if pr_url == "local-fix-applied":
            console.print(Panel(
                "[bold green]Finding Resolved Locally[/bold green]\n\n"
                "A fix was generated in the temporary workspace, but a Pull Request cannot "
                "be opened for local scans. Please check the scan results for details.",
                title=f"Finding: {data.get('title', 'Unknown')}"
            ))
        elif pr_url:
            console.print(Panel(
                f"[bold green]Resolution PR URL:[/bold green]\n{pr_url}", 
                title=f"Finding: {data.get('title', 'Unknown')}"
            ))
        else:
            console.print(Panel(
                "[bold yellow]This finding is marked as fixed, but no PR URL was recorded.[/bold yellow]",
                title="Status"
            ))

    except Exception as e:
        if hasattr(e, "response") and e.response is not None:
            if e.response.status_code == 404:
                console.print(f"[bold red]Error:[/bold red] Finding '{finding_id}' not found.")
            else:
                console.print(f"[bold red]Error:[/bold red] {e.response.text}")
        else:
            console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def check(
    scan_id: str = typer.Argument(..., help="The UUID of the scan to verify"),
    fail: bool = typer.Option(False, "--fail", help="Exit with non-zero code if vulnerabilities are found"),
    severity: str = typer.Option("HIGH", "--severity", help="Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)")
):
    """
    CI/CD Pipeline Check: Wait for scan completion and verify results.
    Exits with code 1 if vulnerabilities matching the threshold are found and --fail is set.
    """
    url = get_url(f"/scans/{scan_id}")
    headers = get_headers()
    
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    threshold = severity.upper()
    if threshold not in severity_order:
        console.print(f"[bold red]Error:[/bold red] Invalid severity '{severity}'. Use LOW, MEDIUM, HIGH, or CRITICAL.")
        raise typer.Exit(code=1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task(description="Waiting for scan to complete...", total=None)
        
        while True:
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                status = data.get("status", "unknown")
                
                if status in ("completed", "failed", "error"):
                    break
                
                progress.update(task, description=f"Scan {scan_id} is [bold cyan]{status}[/bold cyan]. Waiting...")
                time.sleep(5)
            except Exception as e:
                console.print(f"[bold red]Error fetching status:[/bold red] {e}")
                raise typer.Exit(code=1)

    # Scan is done, process findings
    findings_list = data.get("findings", [])
    relevant_findings = [
        f for f in findings_list 
        if severity_order.get(f.get("severity", "LOW").upper(), 0) >= severity_order[threshold]
        and not f.get("is_fixed", False)
    ]

    if not relevant_findings:
        console.print(Panel(
            f"Scan Status: [bold green]{data['status']}[/bold green]\n"
            f"No open findings found at or above [bold yellow]{threshold}[/bold yellow] severity.",
            title="Scan Pass"
        ))
        raise typer.Exit(code=0)

    # Findings exist
    table = Table(title=f"Open Findings (>= {threshold}) for Scan: {scan_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="white")
    table.add_column("File Path", style="yellow")

    for f in relevant_findings:
        table.add_row(
            f["id"],
            f.get("severity", "N/A"),
            f.get("title", "Unknown"),
            f"{f.get('file_path', 'N/A')}:{f.get('line_number', '')}" if f.get("line_number") else f.get("file_path", "N/A")
        )
    
    console.print(table)
    
    if fail:
        console.print(f"\n[bold red]FAILURE:[/bold red] Found {len(relevant_findings)} open vulnerabilities. Failing pipeline as requested.")
        raise typer.Exit(code=1)
    else:
        console.print(f"\n[bold yellow]WARNING:[/bold yellow] Found {len(relevant_findings)} open vulnerabilities. (Exiting with 0 because --fail was not set)")
        raise typer.Exit(code=0)

@app.command()
def usage():
    """View your current quota usage and remaining credits."""
    url = get_url("/user/usage")
    headers = get_headers()

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        console.print(Panel(
            f"[bold cyan]Scans Used:[/bold cyan] {data['scans_used']} / {data['scan_quota_limit']}\n"
            f"[bold cyan]Resolutions:[/bold cyan] {data['resolutions_used']} / {data['resolve_quota_limit']}\n"
            f"[bold green]Credits Remaining:[/bold green] {data['percentage_credit_left']}%",
            title="Account Usage"
        ))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def whoami():
    """Check current authentication status and profile."""
    url = get_url("/user/profile")
    headers = get_headers()

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        console.print(Panel(
            f"[bold cyan]Email:[/bold cyan] {data['email']}\n"
            f"[bold cyan]Plan:[/bold cyan] {data['plan'].upper()}\n"
            f"[bold cyan]Superuser:[/bold cyan] {'Yes' if data['is_superuser'] else 'No'}",
            title="Profile Information"
        ))
    except Exception as e:
        console.print(f"[bold red]Authentication Error:[/bold red] {e}")

if __name__ == "__main__":
    app(prog_name="scp-cli")
