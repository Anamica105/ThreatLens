import type { ResearchStatus, ResultStatus, Severity, Verdict } from "./types";

export type Tone = "neutral" | "muted" | "accent" | "info" | "success" | "warning" | "danger" | "critical";

export const SEVERITY: Record<Severity, { label: string; solid: string; text: string; soft: string }> = {
  critical: { label: "Critical", solid: "var(--sev-critical)", text: "var(--sev-critical-text)", soft: "var(--sev-critical-soft)" },
  high: { label: "High", solid: "var(--sev-high)", text: "var(--sev-high-text)", soft: "var(--sev-high-soft)" },
  medium: { label: "Medium", solid: "var(--sev-medium)", text: "var(--sev-medium-text)", soft: "var(--sev-medium-soft)" },
  low: { label: "Low", solid: "var(--sev-low)", text: "var(--sev-low-text)", soft: "var(--sev-low-soft)" },
  informational: { label: "Informational", solid: "var(--sev-info)", text: "var(--sev-info-text)", soft: "var(--sev-info-soft)" },
};
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export const RESEARCH_STATUS: Record<ResearchStatus, { label: string; tone: Tone }> = {
  draft: { label: "Draft", tone: "neutral" },
  running: { label: "Running", tone: "accent" },
  in_review: { label: "In review", tone: "info" },
  published: { label: "Published", tone: "success" },
  archived: { label: "Archived", tone: "muted" },
  failed: { label: "Failed", tone: "danger" },
};

export const RESULT_STATUS: Record<ResultStatus, { label: string; tone: Tone; icon: string }> = {
  confirmed: { label: "Confirmed compromise", tone: "critical", icon: "octagon-alert" },
  suspicious: { label: "Suspicious", tone: "warning", icon: "triangle-alert" },
  no_evidence: { label: "No evidence", tone: "success", icon: "circle-check" },
  not_applicable: { label: "Not applicable", tone: "neutral", icon: "circle-minus" },
  pending: { label: "Pending", tone: "info", icon: "clock" },
};

export const QUERY_STATUS: Record<string, { label: string; tone: Tone }> = {
  generated: { label: "Generated", tone: "neutral" },
  syntax_checked: { label: "Syntax-checked", tone: "info" },
  reviewed: { label: "Reviewed", tone: "accent" },
  lab_tested: { label: "Lab-tested", tone: "success" },
  deployed: { label: "Deployed", tone: "success" },
  deprecated: { label: "Deprecated", tone: "muted" },
  reference: { label: "Vendor reference", tone: "neutral" },
};

export const VERDICT: Record<Verdict, { label: string; tone: Tone }> = {
  malicious: { label: "Malicious", tone: "danger" },
  suspicious: { label: "Suspicious", tone: "warning" },
  benign: { label: "Benign", tone: "success" },
  unknown: { label: "Unknown", tone: "neutral" },
  expired: { label: "Expired", tone: "muted" },
};

export const CLASSIFICATION: Record<string, { label: string; color: string; icon: string }> = {
  vulnerability_exploitation: { label: "CVE", color: "var(--cls-cve)", icon: "bug" },
  cve: { label: "CVE", color: "var(--cls-cve)", icon: "bug" },
  campaign: { label: "Campaign", color: "var(--cls-campaign)", icon: "flag" },
  actor_profile: { label: "Threat actor", color: "var(--cls-actor)", icon: "user-round-search" },
  actor: { label: "Threat actor", color: "var(--cls-actor)", icon: "user-round-search" },
  malware: { label: "Threat intel", color: "var(--cls-intel)", icon: "book-open-text" },
  intel: { label: "Threat intel", color: "var(--cls-intel)", icon: "book-open-text" },
  ttp_trend: { label: "TTP", color: "var(--cls-ttp)", icon: "route" },
  ttp: { label: "TTP", color: "var(--cls-ttp)", icon: "route" },
  behaviour: { label: "Attack behaviour", color: "var(--cls-behaviour)", icon: "activity" },
  opportunity: { label: "Detection opportunity", color: "var(--cls-opportunity)", icon: "scan-search" },
  detection: { label: "Detection", color: "var(--cls-detection)", icon: "code" },
};
export const CLASSIFICATION_FILTERS = ["vulnerability_exploitation", "campaign", "actor_profile", "malware", "ttp_trend"];
export const CLASSIFICATION_NAMES: Record<string, string> = {
  vulnerability_exploitation: "Vulnerability exploitation", campaign: "Campaign", actor_profile: "Actor profile", malware: "Malware", ttp_trend: "TTP trend",
};

export const QUERY_TYPE: Record<string, string> = { ioc: "IoC", ioa: "IoA", vuln: "Vulnerability", ttp: "TTP" };

export const TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] as const;
export const TLP_SQUARE: Record<string, string> = {
  RED: "var(--tlp-red)", AMBER: "var(--tlp-amber)", "AMBER+STRICT": "var(--tlp-amber)", GREEN: "var(--tlp-green)", CLEAR: "var(--tlp-clear)",
};

export const HORIZON: Record<string, string> = { immediate: "Immediate (0–48 h)", short_term: "Short term (≤ 30 days)", strategic: "Strategic" };

export const IOC_TYPE_LABEL: Record<string, string> = {
  ipv4: "IPv4", ipv6: "IPv6", domain: "Domain", url: "URL", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5", file_name: "File name",
  file_path: "File path", email: "Email", registry: "Registry key", user_agent: "User agent", wallet: "Crypto wallet", mutex: "Mutex", other: "Other",
};

export const DATA_SOURCES: Record<string, string> = {
  process_creation: "Process creation", file_event: "File creation", web: "Web server requests", network: "Network connections",
  dns: "DNS", registry: "Registry", scheduled_task: "Scheduled task / GPO", file_hash: "File hashes", vuln_mgmt: "Vulnerability / asset inventory",
  auth: "Authentication",
};

export const CATEGORICAL = ["#5249A8", "#2F8580", "#B8790F", "#A8456F", "#3A6EA8", "#5B8337", "#85603F", "#6A7384"];

export const RELIABILITY: Record<string, string> = {
  A: "Completely reliable", B: "Usually reliable", C: "Fairly reliable", D: "Not usually reliable", E: "Unreliable", F: "Reliability cannot be judged",
};
export const CREDIBILITY: Record<number, string> = {
  1: "Confirmed", 2: "Probably true", 3: "Possibly true", 4: "Doubtfully true", 5: "Improbable", 6: "Truth cannot be judged",
};
