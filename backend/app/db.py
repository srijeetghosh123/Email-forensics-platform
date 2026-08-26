"""
Persistence layer. Uses SQLite by default (zero-config, fine for a
hackathon demo) and switches to Postgres automatically if a
DATABASE_URL env var is set (e.g. on Render). Same models, same code,
no changes needed to move from demo to a shared production database.
"""
import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./cases.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    subject = Column(String, nullable=True)
    score = Column(Integer)
    verdict = Column(String)
    from_domain = Column(String, nullable=True, index=True)
    reply_domain = Column(String, nullable=True, index=True)
    target_ip = Column(String, nullable=True, index=True)
    full_result = Column(JSON)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
