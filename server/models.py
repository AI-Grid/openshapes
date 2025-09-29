"""Database models for the OpenShapes manager application."""

from __future__ import annotations

import datetime as dt
from typing import Optional

from flask_login import UserMixin
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, scoped_session, sessionmaker


class Base(DeclarativeBase):
    pass


class User(Base, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    discord_id: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, nullable=False)

    def get_id(self) -> str:  # pragma: no cover - used by flask-login
        return str(self.id)


class AgentConfig(Base):
    __tablename__ = "agent_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    base_url: Mapped[str] = mapped_column(String(255), default="https://api.openai.com/v1")
    model: Mapped[str] = mapped_column(String(120), default="gpt-3.5-turbo")
    api_key: Mapped[Optional[str]] = mapped_column(String(128))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    vector_path: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, nullable=False)

    agents: Mapped[list["Agent"]] = relationship("Agent", back_populates="config", cascade="all, delete-orphan")


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    config_id: Mapped[int] = mapped_column(ForeignKey("agent_configs.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="stopped")
    last_heartbeat: Mapped[Optional[dt.datetime]] = mapped_column(DateTime)
    process_id: Mapped[Optional[int]] = mapped_column(Integer)

    config: Mapped[AgentConfig] = relationship("AgentConfig", back_populates="agents")


class Subject(Base):
    __tablename__ = "subjects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    opaque_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    hmac_secret: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    limits: Mapped[Optional["SubjectLimit"]] = relationship(
        "SubjectLimit", uselist=False, back_populates="subject", cascade="all, delete-orphan"
    )
    usage: Mapped[list["SubjectUsage"]] = relationship(
        "SubjectUsage", back_populates="subject", cascade="all, delete-orphan"
    )


class Usage(Base):
    __tablename__ = "usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, nullable=False)
    subject_id: Mapped[int] = mapped_column(ForeignKey("subjects.id"), nullable=False)
    agent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("agents.id"))
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    images_generated: Mapped[int] = mapped_column(Integer, default=0)


class SubjectUsage(Base):
    __tablename__ = "subject_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_id: Mapped[int] = mapped_column(ForeignKey("subjects.id"), nullable=False)
    month: Mapped[int] = mapped_column(Integer, nullable=False)
    year: Mapped[int] = mapped_column(Integer, nullable=False)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    images_generated: Mapped[int] = mapped_column(Integer, default=0)

    subject: Mapped[Subject] = relationship("Subject", back_populates="usage")


class SubjectLimit(Base):
    __tablename__ = "subject_limits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_id: Mapped[int] = mapped_column(ForeignKey("subjects.id"), unique=True, nullable=False)
    monthly_token_limit: Mapped[int] = mapped_column(Integer, default=0)
    monthly_image_limit: Mapped[int] = mapped_column(Integer, default=0)

    subject: Mapped[Subject] = relationship("Subject", back_populates="limits")


class UsageCounter:
    """Helper to summarise usage statistics."""

    def __init__(self, session):
        self.session = session

    def totals(self) -> dict:
        total_tokens = self.session.query(func.sum(Usage.tokens_used)).scalar() or 0
        total_images = self.session.query(func.sum(Usage.images_generated)).scalar() or 0
        return {"tokens": total_tokens, "images": total_images}


def create_session_factory(database_url: str):
    engine = create_engine(database_url, echo=False, future=True)
    Base.metadata.create_all(engine)
    return scoped_session(sessionmaker(bind=engine, expire_on_commit=False))


__all__ = [
    "User",
    "Agent",
    "AgentConfig",
    "Subject",
    "Usage",
    "SubjectUsage",
    "SubjectLimit",
    "UsageCounter",
    "create_session_factory",
]
