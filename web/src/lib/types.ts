export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type ResearchStatus = "draft" | "running" | "in_review" | "published" | "archived" | "failed";
export type ResultStatus = "confirmed" | "suspicious" | "no_evidence" | "not_applicable" | "pending";
export type Verdict = "malicious" | "suspicious" | "benign" | "unknown" | "expired";
export type Tlp = "RED" | "AMBER" | "AMBER+STRICT" | "GREEN" | "CLEAR";

export interface User { id: string; name: string; email: string; role: string; initials: string }

export interface Workspace {
  id: string; name: string; industry: string; color: string; platforms: string[];
  field_mappings: Record<string, Record<string, string>>; log_sources: string[]; products: string[];
  branding: { primary?: string; disclaimer?: string; has_logo?: boolean }; default_tlp: string; research_count?: number;
}

export interface Tactic { id: string; name: string; short: string; count?: number }

export interface Platform { id: string; name: string; short: string; vendor: string }

export interface Meta {
  platforms: Platform[]; categories: Record<string, string>; tactics: Tactic[];
  vendors: { id: string; name: string; reliability: string }[];
  osint_providers: { id: string; name: string; types: string[] }[];
  llm: { available: boolean; model: string }; search: { available: boolean };
  attack: { version: string; techniques: number }; users: User[];
}

export interface ResearchSummary {
  id: string; title: string; status: ResearchStatus; severity: Severity; confidence: string; tlp: Tlp;
  classification: string[]; workspace_ids: string[]; actors: string[]; cves: string[]; malware: string[]; industries: string[];
  counts: { ttps: number; iocs: number; queries: number; sources: number }; platforms: string[];
  result: { workspace_id: string; status: ResultStatus; summary: string } | null;
  results: { workspace_id: string; status: ResultStatus }[];
  created_at: string; updated_at: string; published_at: string | null; author: User | null; rail: Tactic[]; version: number; summary: string;
}

export interface Query {
  id: string; type: "ioc" | "ioa" | "vuln" | "ttp"; title: string; platform: string; body: string; opportunity_id: string | null;
  techniques: string[]; fp_notes: string; data_sources: string[]; log_sources: string[]; status: string; lint: string[];
  origin: "generated" | "reference"; sigma_ref: string | null;
  /** Backend contract (optional until reseeded): sources the detection was derived from. */
  source_ids?: string[];
  /** vendor = published by a source verbatim; derived = built from source evidence; generic = wider technique hunt. */
  provenance?: Provenance;
  /** All platform variants (Sigma, SPL, KQL…) of the same detection logic share one group, e.g. "DET-1". */
  group?: string;
}

export type Provenance = "vendor" | "derived" | "generic";

/** Library detail endpoints: where an entity came from. */
export interface ProvenanceItem {
  research_id: string; research_title?: string; source_id: string; publisher?: string; title?: string; url?: string; quote?: string;
}

export interface MitreRow {
  tactic_id: string; tactic: string; technique_id: string; technique: string; sub_technique: string; procedure: string;
  evidence_quote: string; source_ids: string[]; confidence: string;
}

export interface IocRow {
  type: string; value: string; role: string; context: string; contexts?: string[]; source_ids: string[];
  reputation: Record<string, { summary?: string; [k: string]: unknown }>; reputation_summary: string; verdict: Verdict;
}

export interface Source {
  id: string; url: string; title: string; publisher: string; published: string | null; last_modified: string | null;
  last_fetched: string | null; reliability: string; credibility: number; origin?: string; included: boolean; status: string;
  summary: string; counts: { claims: number; techniques: number; iocs: number; queries: number }; stale?: boolean; type?: string;
}

export interface Opportunity {
  id: string; behaviour_ref: string; title: string; logic: string; type: string; techniques: string[]; fp_notes: string;
  data_sources: string[]; queries: string[]; spec: unknown; source_ids?: string[];
}

export interface AttackPath { id: string; name: string; steps: { ref: string; behaviour: string; technique_id: string; source_ids: string[] }[] }

export interface Conflict {
  topic: string; status: "confirmed" | "disputed" | "superseded"; resolution: string;
  statements: { text: string; source_id: string; date: string }[];
}

export interface ResearchRecord {
  title: string; status: ResearchStatus; tlp: Tlp; classification: string[]; severity: Severity; confidence: string;
  executive_summary: string;
  impact: { severity: Severity; business_impact: string; cia: { confidentiality: boolean; integrity: boolean; availability: boolean }; blast_radius: string };
  patching_insufficient: boolean;
  recommendations: { horizon: "immediate" | "short_term" | "strategic"; action: string; owner_role: string; source_ids: string[] }[];
  results: { workspace_id: string; status: ResultStatus; summary: string; hunt_window: string; queries_run: string[] }[];
  mitre: MitreRow[]; tools_used: { name: string; category: string; detail: string }[];
  workflow: { step: string; actor: string; started_at: string | null; finished_at: string | null; notes: string }[];
  hunts: { queries: Query[]; platforms: string[]; lookback_days: number; ioc_queries: string[]; ioa_queries: string[]; vulnerability_queries: string[]; ttp_queries: string[] };
  industries: { industry: string; evidence: string; source_ids: string[] }[];
  vulnerabilities: { cve: string; cvss: number; epss: number | null; kev_added: string | null; affected_products: string[]; fixed_versions: string[]; patch_kb: string[]; source_ids: string[]; description?: string }[];
  threat_actors: { name: string; aliases: string[]; origin: string; motivation: string[]; attribution_confidence: string; source_ids: string[] }[];
  malware_tools: { name: string; type: string; role: string; source_ids: string[] }[];
  attack_paths: AttackPath[]; ioas: { id: string; description: string; kind: string; source_ids: string[] }[];
  iocs: IocRow[]; detection_opportunities: Opportunity[];
  log_sources_required: ({ data_source: string; label: string } & Record<string, string>)[];
  timeline: { date: string; event: string; source_ids: string[] }[]; sources: Source[];
  claims: { statement: string; source_ids: string[]; status: string }[]; conflicts: Conflict[]; geography: string[];
  study: { background: string; how_it_works: string; kill_chain_narrative: string; remember: string[] };
  tags: string[]; related_research_ids: string[]; affected_technologies: string[];
  applicability?: { workspace_id: string; status: string; reason: string }[];
  coverage_gaps?: { workspace_id: string; behaviour_ref: string; opportunity_id: string; data_source: string; detail: string }[];
  review?: Record<string, string>; _edited?: string[]; demo_note?: string; version?: number;
  run?: { id: string | null; mode: string; tokens: number };
}

export interface ResearchDetail extends ResearchSummary {
  record: ResearchRecord; seed: string; reviewed_by: User | null;
  results: { workspace_id: string; status: ResultStatus; summary: string; hunt_window: string; queries_run: string[]; analyst: User | null; updated_at: string }[];
  workspaces: Record<string, Workspace>; related: { id: string; title: string; severity: Severity; status: ResearchStatus }[];
  run: { id: string; status: string; mode: string; config: Record<string, unknown>; tokens: number; started_at: string | null; finished_at: string | null; active: boolean } | null;
}

export interface RunStage { id: string; label: string; state: "pending" | "running" | "done" | "warning" | "failed"; started_at?: string; finished_at?: string; badge?: string; message?: string }
export interface RunLog { id: number; stage: string; level: string; message: string; created_at: string }
export interface RunDetail {
  id: string; research_id: string; title: string; status: string; mode: string; stage: string; config: Record<string, unknown>;
  started_at: string | null; finished_at: string | null; tokens: number; active: boolean; stages: RunStage[]; logs: RunLog[];
  sources: { id: string; url: string; title: string; publisher: string; reliability: string; origin: string; excluded: boolean; state: string }[];
}
