from logging.config import fileConfig
from pathlib import Path
import sys

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.database import Base
from backend import models
from backend.config import get_settings

config = context.config
settings = get_settings()
# Keep Alembic on the same SQLAlchemy URL as the application engine. In
# particular, standard PostgreSQL URLs must select the installed Psycopg 3
# driver instead of SQLAlchemy's default Psycopg 2 dialect.
sqlalchemy_database_url = settings.sqlalchemy_database_url
config.set_main_option("sqlalchemy.url", sqlalchemy_database_url.replace("%", "%%"))
if config.config_file_name and config.get_section("loggers"):
    fileConfig(config.config_file_name)
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    context.configure(url=sqlalchemy_database_url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})

def run_migrations_online() -> None:
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction(): context.run_migrations()

run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
