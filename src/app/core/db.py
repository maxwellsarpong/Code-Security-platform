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
    
    # Lightweight migration: Add missing columns to finding table if they don't exist
    # This is necessary because SQLModel.metadata.create_all() does not handle schema updates for existing tables.
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('finding')]
    
    with engine.connect() as conn:
        if 'is_fixed' not in columns:
            print("Migration: Adding column 'is_fixed' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN is_fixed BOOLEAN DEFAULT FALSE"))
            conn.commit()
            
        if 'pr_url' not in columns:
            print("Migration: Adding column 'pr_url' to table 'finding'...")
            conn.execute(text("ALTER TABLE finding ADD COLUMN pr_url VARCHAR"))
            conn.commit()
