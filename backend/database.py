import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database URL configuration: default to local sqlite, allow overriding with environment variables for PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tizen_grc_v3.db")

# Create database engine
# Note: connect_args={"check_same_thread": False} is required only for SQLite
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """
    Dependency generator for database sessions.
    Ensures that the database session is closed after the request lifecycle.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
