"""Structured-output schemas for each agent stage. Every claim carries source ids."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Confidence = Literal["high", "moderate", "low"]


class IntakeOut(BaseModel):
    title_guess: str = Field(description="Short working title for the threat")
    cves: list[str]
    actors: list[str]
    malware: list[str]
    products: list[str] = Field(description="Affected products or technologies")
    keywords: list[str] = Field(description="3-8 distinctive search terms (campaign names, nicknames)")


class Claim(BaseModel):
    statement: str
    evidence_quote: str


class TtpNote(BaseModel):
    technique_id: str = Field(description="ATT&CK ID like T1505.003")
    behaviour: str = Field(description="Observable behaviour, concrete (process names, paths, URLs)")
    evidence_quote: str


class ActorNote(BaseModel):
    name: str
    aliases: list[str]
    origin: str
    motivation: list[str]
    attribution_confidence: Confidence


class MalwareNote(BaseModel):
    name: str
    type: Literal["malware", "tool", "lolbin", "webshell", "ransomware", "framework"]
    role: str


class IocNote(BaseModel):
    type: Literal["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "file_name", "file_path", "email", "registry", "user_agent", "wallet", "mutex", "other"]
    value: str
    role: str = Field(description="e.g. exploitation source, C2, payload, dropped file")


class VendorQuery(BaseModel):
    platform: str = Field(description="kql_defender, kql_sentinel, spl, cql, s1ql, xql, esql, yaral, aql or sigma")
    title: str
    query: str


class TimelineNote(BaseModel):
    date: str = Field(description="ISO date YYYY-MM-DD")
    event: str


class SourceNotes(BaseModel):
    summary: str = Field(description="3-5 sentence summary of what this source adds")
    claims: list[Claim]
    ttps: list[TtpNote]
    cves: list[str]
    actors: list[ActorNote]
    malware: list[MalwareNote]
    iocs: list[IocNote]
    ioas: list[str] = Field(description="Behavioural indicators: process chains, HTTP request patterns, file writes")
    timeline: list[TimelineNote]
    industries: list[str]
    regions: list[str]
    vendor_queries: list[VendorQuery]
    recommendations: list[str]


class Cia(BaseModel):
    confidentiality: bool
    integrity: bool
    availability: bool


class Impact(BaseModel):
    severity: Literal["critical", "high", "medium", "low"]
    business_impact: str
    cia: Cia
    blast_radius: str


class Recommendation(BaseModel):
    horizon: Literal["immediate", "short_term", "strategic"]
    action: str
    owner_role: str
    source_ids: list[str]


class ClaimOut(BaseModel):
    statement: str
    source_ids: list[str]
    status: Literal["confirmed", "disputed", "superseded"]


class ConflictStatement(BaseModel):
    text: str
    source_id: str
    date: str


class Conflict(BaseModel):
    topic: str
    statements: list[ConflictStatement]
    status: Literal["confirmed", "disputed", "superseded"]
    resolution: str


class IndustryOut(BaseModel):
    industry: str
    evidence: Literal["observed", "assessed"]
    source_ids: list[str]


class TimelineOut(BaseModel):
    date: str
    event: str
    source_ids: list[str]


class Study(BaseModel):
    background: str
    how_it_works: str
    kill_chain_narrative: str
    remember: list[str] = Field(description="3-6 'what you should remember' bullets")


class NarrativeOut(BaseModel):
    title: str = Field(description="'<Threat/Campaign>: <what> via <vector>', max 120 chars")
    executive_summary: str = Field(description="150-250 words, plain language, no IoCs")
    classification: list[Literal["vulnerability_exploitation", "campaign", "actor_profile", "malware", "ttp_trend"]]
    confidence: Confidence
    impact: Impact
    patching_insufficient: bool
    recommendations: list[Recommendation]
    claims: list[ClaimOut]
    conflicts: list[Conflict]
    industries: list[IndustryOut]
    geography: list[str]
    timeline: list[TimelineOut]
    study: Study


class VulnOut(BaseModel):
    cve: str
    cvss: float
    affected_products: list[str]
    fixed_versions: list[str]
    patch_kb: list[str]
    source_ids: list[str]


class ActorOut(BaseModel):
    name: str
    aliases: list[str]
    origin: str
    motivation: list[str]
    attribution_confidence: Confidence
    source_ids: list[str]


class MalwareOut(BaseModel):
    name: str
    type: Literal["malware", "tool", "lolbin", "webshell", "ransomware", "framework"]
    role: str
    source_ids: list[str]


class PathStep(BaseModel):
    behaviour: str
    technique_id: str
    source_ids: list[str]


class AttackPathOut(BaseModel):
    name: str
    steps: list[PathStep]


class IoaOut(BaseModel):
    description: str
    kind: Literal["process_chain", "http_request", "file_write", "network", "registry", "other"]
    source_ids: list[str]


class EntitiesOut(BaseModel):
    vulnerabilities: list[VulnOut]
    threat_actors: list[ActorOut]
    malware_tools: list[MalwareOut]
    attack_paths: list[AttackPathOut]
    ioas: list[IoaOut]


class MitreOut(BaseModel):
    technique_id: str
    tactic_id: str = Field(description="ATT&CK tactic ID like TA0003 for the tactic this procedure serves")
    procedure: str
    evidence_quote: str
    source_ids: list[str]
    confidence: Confidence


class MitreList(BaseModel):
    mitre: list[MitreOut]


class SpecCondition(BaseModel):
    field: Literal["parent_image", "grandparent_image", "image", "command_line", "target_filename", "http_method", "url_path",
                   "referer", "user_agent", "src_ip", "dst_ip", "domain", "sha256"]
    op: Literal["equals", "endswith", "contains", "startswith"]
    values: list[str]


class DetectionSpec(BaseModel):
    category: Literal["process_creation", "file_event", "web", "network", "dns", "file_hash"]
    conditions: list[SpecCondition]


class OpportunityOut(BaseModel):
    behaviour_ref: str = Field(description="Attack-path step reference like AP-1.2")
    title: str
    logic: str
    type: Literal["ioa", "ttp"]
    techniques: list[str]
    fp_notes: str
    spec: DetectionSpec


class OpportunityList(BaseModel):
    opportunities: list[OpportunityOut]


class PlatformQuery(BaseModel):
    opportunity_id: str
    platform: str
    query: str


class QueryList(BaseModel):
    queries: list[PlatformQuery]
