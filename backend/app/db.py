"""Modelos de datos (SQLAlchemy) y sesión de BD. Ver PLAN.md §12."""
import datetime as dt

from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer, String,
                        create_engine)
from sqlalchemy.orm import declarative_base, sessionmaker

from . import config

engine = create_engine(config.DB_URL, connect_args={"check_same_thread": False} if config.DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def now():
    return dt.datetime.utcnow()


class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True)
    password_hash = Column(String, nullable=False)
    role_override = Column(String, nullable=True)  # 'dev' | 'student' | None (deducir del nodo)
    created_at = Column(DateTime, default=now)


class Catalog(Base):
    __tablename__ = "catalog"
    id = Column(String, primary_key=True)  # colab | python | postgres
    name = Column(String)
    description = Column(String, default="")
    image = Column(String)
    cpu = Column(String)
    mem = Column(String)
    gpu = Column(Boolean, default=False)
    ports_json = Column(String, default="")   # "8080" o "8080,5432"
    access = Column(String, default="web")    # web | tcp | console
    env_json = Column(String, default="")     # JSON de variables de entorno


class Env(Base):
    __tablename__ = "envs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    owner = Column(String, nullable=False)
    node = Column(String, nullable=False)
    catalog_id = Column(String, nullable=False)
    nodeport = Column(Integer, nullable=True)
    status = Column(String, default="running")  # running | stopped | deleting
    gpu = Column(Integer, default=0)  # 1 = creado con GPU (badge en la UI)
    created_at = Column(DateTime, default=now)
    last_activity = Column(DateTime, default=now)
    stopped_at = Column(DateTime, nullable=True)


class ActivityLog(Base):
    __tablename__ = "activity_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    env_id = Column(Integer, ForeignKey("envs.id"), nullable=True)
    username = Column(String)
    action = Column(String)  # create|open|stop|start|delete|auto-stop|auto-delete
    ts = Column(DateTime, default=now)


def init_db():
    Base.metadata.create_all(engine)


def db_session():
    return SessionLocal()
