import datetime
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255))
    program_url: Mapped[str] = mapped_column(String(500), default="")
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    url: Mapped[str] = mapped_column(String(1000))
    modules: Mapped[str] = mapped_column(String(500))  # comma separated
    status: Mapped[str] = mapped_column(String(50), default="queued")
    progress: Mapped[str] = mapped_column(String(255), default="")
    started_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.utcnow)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    category: Mapped[str] = mapped_column(String(100))       # e.g. A03:2021-Injection
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20))        # info/low/medium/high/critical
    confidence: Mapped[str] = mapped_column(String(20))      # confirmed/likely/info
    location: Mapped[str] = mapped_column(String(1000))
    evidence: Mapped[str] = mapped_column(Text, default="")
    poc: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
