import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

class Base(DeclarativeBase):
    pass

def database_url():
    path = os.getenv("DATABASE_URL_FILE")
    return Path(path).read_text().strip() if path else os.environ["DATABASE_URL"]

def session_factory():
    return sessionmaker(create_engine(database_url(), pool_pre_ping=True))
