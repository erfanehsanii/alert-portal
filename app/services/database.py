
import os
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg import Connection


def get_database_connection() -> Connection:
    """Create a PostgreSQL connection using environment configuration."""
    return psycopg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        connect_timeout=3,
    )


@contextmanager
def database_connection() -> Iterator[Connection]:
    """Yield a connection and ensure it is closed afterward."""
    connection = get_database_connection()
    try:
        yield connection
    finally:
        connection.close()
