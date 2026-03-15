import typer
import requests
import json
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from typing import Optional
from uuid import UUID

from app import __version__

app = typer.Typer(
    help="Security Compliance Platform CLI - Secure your code from the terminal.",
    add_completion=False
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
    repo_url: str = typer.Argument(..., help="URL of the repository to scan"),
    token: Optional[str] = typer.Option(None, help="GitHub/GitLab Personal Access Token for private repos")
):
    """Trigger a new security scan for a repository."""
    url = get_url("/scans")
    headers = get_headers()
    payload = {"repo_url": repo_url}
    if token:
        payload["github_token"] = token

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Triggering scan...", total=None)
        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            console.print(Panel(
                f"[bold cyan]Scan ID:[/bold cyan] {data['id']}\n"
                f"[bold cyan]Status:[/bold cyan] {data['status']}\n"
                f"[bold cyan]Repository:[/bold cyan] {repo_url}",
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
def resolve(
    target_id: str = typer.Argument(..., help="Finding ID or Scan ID to resolve"),
    token: Optional[str] = typer.Option(None, help="GitHub token (if not saved in profile)")
):
    """Trigger automated resolution for a finding or an entire scan."""
    url = get_url(f"/findings/{target_id}/resolve")
    headers = get_headers()
    payload = {}
    if token:
        payload["github_token"] = token

    with Progress(SpinnerColumn(), transient=True) as progress:
        progress.add_task(description="Requesting resolution...", total=None)
        try:
            response = requests.post(url, json=payload, headers=headers)
            data = response.json()
            
            if response.status_code == 200:
                console.print(Panel(
                    f"[bold green]Status:[/bold green] {data['status']}\n"
                    f"[bold white]Message:[/bold white] {data['message']}",
                    title="Resolution Started"
                ))
            else:
                console.print(f"[bold red]Failed:[/bold red] {data.get('detail', 'Unknown error')}")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")

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
        response.raise_for_status()
        data = response.json()

        if not data.get("is_fixed"):
            console.print(Panel(f"[bold yellow]Finding {finding_id} is not marked as resolved yet.[/bold yellow]", title="Status"))
            return

        pr_url = data.get("pr_url")
        if pr_url:
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
    app()
