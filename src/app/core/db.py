from sqlmodel import create_engine, Session, SQLModel
import os
import logging
from .config import Settings

logger = logging.getLogger(__name__)

settings = Settings()
DATABASE_URL = os.getenv("DATABASE_URL", settings.database_url)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

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
            logger.info("Migration: Adding column 'is_fixed' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN is_fixed BOOLEAN DEFAULT FALSE"))
            conn.commit()
        if 'pr_url' not in finding_cols:
            logger.info("Migration: Adding column 'pr_url' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN pr_url VARCHAR"))
            conn.commit()
        if 'user_id' not in finding_cols:
            logger.info("Migration: Adding column 'user_id' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN user_id VARCHAR"))
            conn.commit()

        # 2. Update 'scan' table
        scan_cols = [col['name'] for col in inspector.get_columns('scan')]
        if 'user_id' not in scan_cols:
            logger.info("Migration: Adding column 'user_id' to table 'scan'...")
            conn.execute(text("ALTER TABLE scan ADD COLUMN user_id VARCHAR"))
            conn.commit()

        # 3. Update 'user' table
        user_cols = [col['name'] for col in inspector.get_columns('user')]
        new_user_cols = [
            'plan', 'rate_limit_per_minute', 'scan_quota_per_month', 'resolve_quota_per_month',
            'slack_webhook_url', 'jira_url', 'jira_email', 'jira_api_token',
            'jira_project_key', 'github_token', 'gitlab_token', 'bitbucket_token', 'is_superuser'
        ]
        for col in new_user_cols:
            if col not in user_cols:
                # Choose the right type and default per column
                if col in ('scan_quota_per_month', 'resolve_quota_per_month'):
                    col_type = "INTEGER DEFAULT 2"
                elif col == 'rate_limit_per_minute':
                    col_type = "INTEGER DEFAULT 10"
                elif col == 'is_superuser':
                    col_type = "BOOLEAN DEFAULT FALSE"
                else:
                    col_type = "VARCHAR"

                logger.info(f"Migration: Adding column '{col}' to table 'user'...")
                conn.execute(text(f"ALTER TABLE user ADD COLUMN {col} {col_type}"))
                conn.commit()
