from alembic import context
from sqlalchemy import create_engine
from nous.db import Base, database_url
from nous import models  # noqa: F401

config = context.config
target_metadata = Base.metadata

def run_migrations_online():
    engine = create_engine(database_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

run_migrations_online()
