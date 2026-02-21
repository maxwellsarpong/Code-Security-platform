from sqlmodel import create_engine, Session, SQLModel
import os
from .config import Settings

settings = Settings()
DATABASE_URL = os.getenv("DATABASE_URL", settings.database_url)

engine = create_engine(DATABASE_URL, echo=False)

def get_session():
    with Session(engine) as session:
        yield session

def init_db():
    SQLModel.metadata.create_all(engine)
    
    # Lightweight migration: Add missing columns if they don't exist
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    
    with engine.connect() as conn:
        # 1. Update 'finding' table
        finding_cols = [col['name'] for col in inspector.get_columns('finding')]
        if 'is_fixed' not in finding_cols:
            print("Migration: Adding column 'is_fixed' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN is_fixed BOOLEAN DEFAULT FALSE"))
            conn.commit()
        if 'pr_url' not in finding_cols:
            print("Migration: Adding column 'pr_url' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN pr_url VARCHAR"))
            conn.commit()
        if 'tenant_id' not in finding_cols:
            print("Migration: Adding column 'tenant_id' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN tenant_id VARCHAR"))
            conn.commit()

        # 2. Update 'scan' table
        scan_cols = [col['name'] for col in inspector.get_columns('scan')]
        if 'tenant_id' not in scan_cols:
            print("Migration: Adding column 'tenant_id' to table 'scan'...")
            conn.execute(text("ALTER TABLE scan ADD COLUMN tenant_id VARCHAR"))
            conn.commit()

        # 3. Update 'tenant' table for integration configs
        tenant_cols = [col['name'] for col in inspector.get_columns('tenant')]
        new_tenant_cols = [
            'slack_webhook_url', 'jira_url', 'jira_email', 'jira_api_token', 
            'jira_project_key', 'github_token', 'gitlab_token', 'bitbucket_token'
        ]
        for col in new_tenant_cols:
            if col not in tenant_cols:
                print(f"Migration: Adding column '{col}' to table 'tenant'...")
                conn.execute(text(f"ALTER TABLE tenant ADD COLUMN {col} VARCHAR"))
                conn.commit()
