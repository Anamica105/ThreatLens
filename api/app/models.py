"""Relational model (spec section 11).

The full research record lives in `Research.record` as a versioned JSON snapshot.
Library entities (actors, malware, CVEs, IoCs, queries, techniques) are normalised
into their own tables and linked to research through `ResearchLink`, which is what
lets every library show "Seen in research".
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, Float
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "user"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(200), unique=True)
    role: Mapped[str] = mapped_column(String(20), default="hunter")  # hunter, reviewer, lead, admin
    initials: Mapped[str] = mapped_column(String(4), default="")
    preferences: Mapped[dict] = mapped_column(JSON, default=dict)


class Workspace(Base):
    __tablename__ = "workspace"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    industry: Mapped[str] = mapped_column(String(80), default="")
    color: Mapped[str] = mapped_column(String(9), default="#5249A8")
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    field_mappings: Mapped[dict] = mapped_column(JSON, default=dict)
    log_sources: Mapped[list] = mapped_column(JSON, default=list)
    products: Mapped[list] = mapped_column(JSON, default=list)  # technology in scope, drives applicability
    branding: Mapped[dict] = mapped_column(JSON, default=dict)
    default_tlp: Mapped[str] = mapped_column(String(20), default="AMBER")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Research(Base):
    __tablename__ = "research"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft, running, in_review, published, archived, failed
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    confidence: Mapped[str] = mapped_column(String(20), default="moderate")
    tlp: Mapped[str] = mapped_column(String(20), default="AMBER")
    classification: Mapped[list] = mapped_column(JSON, default=list)
    workspace_ids: Mapped[list] = mapped_column(JSON, default=list)
    seed: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str | None] = mapped_column(ForeignKey("user.id"), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("user.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    search_text: Mapped[str] = mapped_column(Text, default="")
    record: Mapped[dict] = mapped_column(JSON, default=dict)


class ResearchVersion(Base):
    __tablename__ = "research_version"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    research_id: Mapped[str] = mapped_column(ForeignKey("research.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    record: Mapped[dict] = mapped_column(JSON)
    changed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    summary: Mapped[str] = mapped_column(Text, default="")
    diff: Mapped[dict] = mapped_column(JSON, default=dict)


class Run(Base):
    __tablename__ = "run"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    research_id: Mapped[str] = mapped_column(ForeignKey("research.id", ondelete="CASCADE"), index=True)
    seed: Mapped[str] = mapped_column(Text, default="")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, running, done, failed, cancelled
    stage: Mapped[str] = mapped_column(String(40), default="intake")
    stage_status: Mapped[dict] = mapped_column(JSON, default=dict)
    artifacts: Mapped[dict] = mapped_column(JSON, default=dict)  # per-stage outputs, so stages can re-run alone
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cost_tokens: Mapped[int] = mapped_column(Integer, default=0)
    mode: Mapped[str] = mapped_column(String(20), default="llm")  # llm, offline


class RunLog(Base):
    __tablename__ = "run_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(40))
    level: Mapped[str] = mapped_column(String(10), default="info")
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Result(Base):
    __tablename__ = "result"
    __table_args__ = (UniqueConstraint("research_id", "workspace_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    research_id: Mapped[str] = mapped_column(ForeignKey("research.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspace.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # no_evidence, suspicious, confirmed, not_applicable, pending
    summary: Mapped[str] = mapped_column(Text, default="")
    hunt_window: Mapped[str] = mapped_column(String(80), default="")
    queries_run: Mapped[list] = mapped_column(JSON, default=list)
    analyst_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Actor(Base):
    __tablename__ = "actor"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)  # slug
    name: Mapped[str] = mapped_column(String(120))
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    origin: Mapped[str] = mapped_column(String(120), default="")
    motivation: Mapped[list] = mapped_column(JSON, default=list)
    target_industries: Mapped[list] = mapped_column(JSON, default=list)
    target_regions: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MalwareTool(Base):
    __tablename__ = "malware_tool"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    type: Mapped[str] = mapped_column(String(30), default="malware")  # malware, tool, lolbin, webshell, ransomware
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    capabilities: Mapped[str] = mapped_column(Text, default="")
    hashes: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerability"
    cve: Mapped[str] = mapped_column(String(30), primary_key=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_added: Mapped[str | None] = mapped_column(String(20), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    affected_products: Mapped[list] = mapped_column(JSON, default=list)
    patch_kb: Mapped[list] = mapped_column(JSON, default=list)


class Ioc(Base):
    __tablename__ = "ioc"
    __table_args__ = (UniqueConstraint("type", "value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(600))  # stored refanged; always displayed defanged
    verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    reputation: Mapped[dict] = mapped_column(JSON, default=dict)
    context: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Query(Base):
    __tablename__ = "query"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # Q-0007
    title: Mapped[str] = mapped_column(String(200))
    platform: Mapped[str] = mapped_column(String(30))
    type: Mapped[str] = mapped_column(String(10))  # ioc, ioa, vuln, ttp
    body: Mapped[str] = mapped_column(Text)
    sigma_ref: Mapped[str | None] = mapped_column(String(40), nullable=True)
    log_sources: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    fp_notes: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="generated")
    version: Mapped[int] = mapped_column(Integer, default=1)
    origin: Mapped[str] = mapped_column(String(20), default="generated")  # generated, reference (vendor-supplied)
    deployed_workspaces: Mapped[list] = mapped_column(JSON, default=list)
    last_hit: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AttackTechnique(Base):
    __tablename__ = "attack_technique"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # T1505.003
    name: Mapped[str] = mapped_column(String(200))
    tactic_ids: Mapped[list] = mapped_column(JSON, default=list)
    attack_version: Mapped[str] = mapped_column(String(20), default="")


class ResearchLink(Base):
    """Many-to-many links between research and library entities."""

    __tablename__ = "research_link"
    __table_args__ = (UniqueConstraint("research_id", "entity_type", "entity_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    research_id: Mapped[str] = mapped_column(ForeignKey("research.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(20), index=True)  # actor, malware, cve, ioc, query, technique
    entity_key: Mapped[str] = mapped_column(String(600), index=True)


class ActivityEvent(Base):
    __tablename__ = "activity_event"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    research_id: Mapped[str | None] = mapped_column(ForeignKey("research.id", ondelete="CASCADE"), index=True, nullable=True)
    type: Mapped[str] = mapped_column(String(30))  # created, run_completed, edited, status, exported, comment, result
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExportLog(Base):
    __tablename__ = "export_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    research_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    workspace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    format: Mapped[str] = mapped_column(String(20))
    scope: Mapped[str] = mapped_column(String(20), default="research")  # research, period
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    file_name: Mapped[str] = mapped_column(String(200), default="")
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExternalCache(Base):
    """Cached responses from public reference feeds (NVD, CISA KEV, FIRST EPSS), keyed e.g. `nvd:CVE-2025-53770`."""

    __tablename__ = "external_cache"
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """Audit log of views (spec section 13). Edits and exports live in activity_event / export_log."""

    __tablename__ = "audit_event"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(20), default="view")
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(20), index=True)  # research, actor, malware, query, ioc, cve
    entity_id: Mapped[str] = mapped_column(String(600), index=True)
    path: Mapped[str] = mapped_column(String(600), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Setting(Base):
    __tablename__ = "setting"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class Counter(Base):
    __tablename__ = "counter"
    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)
