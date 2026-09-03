"""
Database connection and session management for SOC Causal Correlation system
Handles PostgreSQL connection pooling, session creation, and database initialization
"""

import os
import logging
from typing import Generator, Optional
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from dotenv import load_dotenv

from .models import Base

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
 "postgresql://postgres:ConceptFlow26@localhost:5432/rootline"
)
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))  # 1 hour
DB_ECHO = os.getenv("DB_ECHO", "false").lower() == "true"

# Global engine and session factory
engine: Optional[Engine] = None
SessionLocal: Optional[sessionmaker] = None


def create_database_engine(database_url: str = DATABASE_URL) -> Engine:
    """
    Create PostgreSQL engine with connection pooling

    Args:
        database_url: PostgreSQL connection URL

    Returns:
        SQLAlchemy Engine instance
    """
    global engine

    if engine is not None:
        return engine

    logger.info(f"Creating database engine for: {database_url}")

    engine = create_engine(
        database_url,
        poolclass=QueuePool,
        pool_size=DB_POOL_SIZE,
        max_overflow=DB_MAX_OVERFLOW,
        pool_timeout=DB_POOL_TIMEOUT,
        pool_recycle=DB_POOL_RECYCLE,
        echo=DB_ECHO,
        future=True  # Use SQLAlchemy 2.0 style
    )

    # Add connection event listeners for logging
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        """Set PostgreSQL connection parameters"""
        logger.debug("New database connection established")

    @event.listens_for(engine, "checkout")
    def receive_checkout(dbapi_connection, connection_record, connection_proxy):
        """Log connection checkout"""
        logger.debug("Connection checked out from pool")

    return engine


def get_engine() -> Engine:
    """
    Get the global database engine, creating it if necessary

    Returns:
        SQLAlchemy Engine instance
    """
    global engine
    if engine is None:
        engine = create_database_engine()
    return engine


def create_session_factory(engine: Optional[Engine] = None) -> sessionmaker:
    """
    Create session factory bound to the given engine

    Args:
        engine: SQLAlchemy Engine instance (optional, uses global if not provided)

    Returns:
        Configured sessionmaker
    """
    global SessionLocal

    if engine is None:
        engine = get_engine()

    if SessionLocal is not None:
        return SessionLocal

    SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
        expire_on_commit=False
    )

    return SessionLocal


def get_session() -> Generator[Session, None, None]:
    """
    Dependency that provides a transactional scope around a series of operations

    Yields:
        SQLAlchemy Session

    Example:
        with get_session() as session:
            # perform database operations
            session.add(some_object)
            session.commit()
    """
    if SessionLocal is None:
        create_session_factory()

    session = SessionLocal()
    try:
        yield session
    except Exception as e:
        logger.error(f"Database session error: {e}")
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for database sessions

    Yields:
        SQLAlchemy Session

    Example:
        with get_db_context() as session:
            # perform database operations
            session.add(some_object)
            session.commit()
    """
    if SessionLocal is None:
        create_session_factory()

    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        logger.error(f"Database context error: {e}")
        session.rollback()
        raise
    finally:
        session.close()


def init_database(drop_first: bool = False) -> None:
    """
    Initialize database tables

    Args:
        drop_first: If True, drop all tables before creating them
    """
    engine = get_engine()

    if drop_first:
        logger.warning("Dropping all existing tables")
        Base.metadata.drop_all(bind=engine)
        logger.info("All tables dropped")

    logger.info("Creating database tables")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


def check_database_connection() -> bool:
    """
    Check if database connection is working

    Returns:
        True if connection is successful, False otherwise
    """
    try:
        engine = get_engine()
        with engine.connect() as connection:
            connection.execute("SELECT 1")
        logger.info("Database connection successful")
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False


def get_database_info() -> dict:
    """
    Get basic information about the database

    Returns:
        Dictionary with database information
    """
    try:
        engine = get_engine()
        with engine.connect() as connection:
            # Get PostgreSQL version
            version_result = connection.execute("SELECT version()")
            version = version_result.fetchone()[0]

            # Get database size
            size_result = connection.execute(
                "SELECT pg_size_pretty(pg_database_size(current_database()))"
            )
            size = size_result.fetchone()[0]

            # Get table count
            tables_result = connection.execute("""
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'public'
            """)
            table_count = tables_result.fetchone()[0]

        return {
            "connected": True,
            "postgresql_version": version,
            "database_size": size,
            "table_count": table_count,
            "database_url": str(engine.url).replace(
                engine.url.password or "", "****"
            ) if engine.url.password else str(engine.url)
        }
    except Exception as e:
        logger.error(f"Failed to get database info: {e}")
        return {
            "connected": False,
            "error": str(e)
        }


# Initialize engine and session factory on module import
# Comment this out if you prefer lazy initialization
# get_engine()
# create_session_factory()