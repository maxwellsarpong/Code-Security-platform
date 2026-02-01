from pydantic_settings import BaseSettings


import os
class Settings(BaseSettings):
    project_name: str = "security-compliance-platform"
    # Use absolute path to avoid SQLite errors
    database_url: str = f"sqlite:///{os.path.join(os.getcwd(), 'dev.db')}"
    scanner_worker_concurrency: int = 2
    
    # Scanner configuration
    scanner_timeout: int = 300  # 5 minutes
    scanner_temp_dir: str = "/tmp/scans"
    enabled_scanners: str = "bandit,checkov,pip-audit"  # Comma-separated list

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
