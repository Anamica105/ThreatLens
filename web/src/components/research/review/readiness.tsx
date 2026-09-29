"use client";

import clsx from "clsx";
import { CircleCheck, ShieldAlert, TriangleAlert } from "lucide-react";
import { useState } from "react";
import type { MitreRow, ResearchRecord, User } from "@/lib/types";
import { Badge } from "../../ui/badges";

/** GET /api/research/{id}/readiness — grounding gate (spec §12). Also the body of a 409 from publish (plus `detail`). */
export interface ReadinessIssue {
  section: "claims" | "recommendations" | "mitre" | "industries" | "threat_actors" | "malware_tools" | "vulnerabilities" | "attack_paths" | "conflicts";
  index: number;
  step?: number;
  ref?: string;
  field: "source_ids" | "evidence_quote" | "status";
  kind: "missing_source" | "unknown_source" | "quote_not_found" | "disputed_conflict";
  text: string;
  severity: "block" | "warn";
  anchor: string;
  unknown_ids?: string[];
}
export interface Readiness { ready: boolean; blocking: number; warnings: number; issues: ReadinessIssue[] }

/** Record items edited by a person carry `_edited: true` (set by the API). */
export type Edited<T> = T & { _edited?: boolean };
export const isEdited = (x: unknown) => !!(x && typeof x === "object" && (x as { _edited?: boolean })._edited);

export type MitreRowE = Edited<MitreRow>;
export type AttackPathE = Edited<ResearchRecord["attack_paths"][number]>;

export const REVIEW_ROLES = ["reviewer", "lead", "admin"];
export const isReviewer = (u: User | null | undefined) => !!u && REVIEW_ROLES.includes(u.role);
/** Hunters may edit drafts; reviewers, leads and admins may edit at any stage (never archived). Mirrors the API. */
export const canReviewEdit = (u: User | null | undefined, status: string) =>
  status !== "archived" && status !== "running" && (isReviewer(u) || status === "draft" || status === "failed");

const SECTION_LABEL: Record<string, string> = {
  claims: "Claim", recommendations: "Recommendation", mitre: "MITRE row", industries: "Industry", threat_actors: "Threat actor",
  malware_tools: "Malware/tool", vulnerabilities: "Vulnerability", attack_paths: "Attack-path step", conflicts: "Conflict",
};
const KIND_LABEL: Record<string, string> = {
  missing_source: "No source cited", unknown_source: "Cites a source not in this report",
  quote_not_found: "Evidence quote not found in the source article", disputed_conflict: "Disputed claim needs a status",
};

export function blockingSummary(r: Readiness) {
  const unsupported = r.issues.filter((i) => i.severity === "block" && i.kind !== "disputed_conflict").length;
  const disputed = r.issues.filter((i) => i.severity === "block" && i.kind === "disputed_conflict").length;
  const parts = [];
  if (unsupported) parts.push(`${unsupported} unsupported statement${unsupported === 1 ? "" : "s"}`);
  if (disputed) parts.push(`${disputed} disputed claim${disputed === 1 ? "" : "s"}`);
  return `${parts.join(" and ")} ${r.blocking === 1 ? "blocks" : "block"} publishing`;
}

/** Small header badge; clicking it opens the panel. */
export function ReadinessBadge({ r, onClick }: { r: Readiness | undefined; onClick?: () => void }) {
  if (!r) return null;
  const tone = r.blocking ? "danger" : r.warnings ? "warning" : "success";
  const label = r.blocking ? blockingSummary(r) : r.warnings ? `Ready · ${r.warnings} warning${r.warnings === 1 ? "" : "s"}` : "Grounding checks pass";
  return (
    <button type="button" onClick={onClick} className="rounded-sm focus-visible:outline-2" aria-label={`Publish readiness: ${label}`}>
      <Badge tone={tone}>{label}</Badge>
    </button>
  );
}

/** Readiness panel: every grounding issue with a jump link to its report section. */
export function ReadinessPanel({ r, onJump, className }: { r: Readiness; onJump: (anchor: string) => void; className?: string }) {
  const [showWarn, setShowWarn] = useState(false);
  const block = r.issues.filter((i) => i.severity === "block");
  const warn = r.issues.filter((i) => i.severity === "warn");
  if (!r.issues.length) {
    return (
      <div id="readiness" className={clsx("flex items-center gap-2 rounded-md border border-line bg-surface px-4 py-3 text-[14px]", className)}>
        <CircleCheck className="size-5 text-[var(--success)]" /> Every statement cites a report source and every checked evidence quote was found in its article.
      </div>
    );
  }
  const tone = block.length ? "danger" : "warning";
  return (
    <section id="readiness" aria-label="Publish readiness" className={clsx("rounded-md border px-4 py-3", className)}
      style={{ background: `var(--${tone}-soft)`, borderColor: `var(--${tone}-border)` }}>
      <div className="flex flex-wrap items-center gap-2">
        {block.length ? <ShieldAlert className="size-5" style={{ color: "var(--danger)" }} /> : <TriangleAlert className="size-5" style={{ color: "var(--warning)" }} />}
        <h2 className="text-h4 font-semibold">{block.length ? blockingSummary(r) : "Ready to publish, with warnings"}</h2>
        {warn.length > 0 && (
          <button type="button" className="ml-auto text-body-sm font-semibold text-accent-text hover:underline" onClick={() => setShowWarn(!showWarn)} aria-expanded={showWarn}>
            {showWarn ? "Hide" : "Show"} {warn.length} warning{warn.length === 1 ? "" : "s"}
          </button>
        )}
      </div>
      {block.length > 0 && <p className="mt-1 text-body-sm text-fg-strong">Cite a source, fix the quote, or edit the statement. A reviewer can also approve the section to accept it as written.</p>}
      <IssueList issues={block} onJump={onJump} />
      {showWarn && (
        <>
          <p className="mt-3 text-caption font-semibold text-fg-muted">Warnings: edited by a person or in an approved section. They do not block publishing.</p>
          <IssueList issues={warn} onJump={onJump} />
        </>
      )}
    </section>
  );
}

function IssueList({ issues, onJump }: { issues: ReadinessIssue[]; onJump: (anchor: string) => void }) {
  if (!issues.length) return null;
  return (
    <ul className="mt-2 space-y-1">
      {issues.map((i, n) => (
        <li key={n} className="flex min-w-0 flex-wrap items-baseline gap-x-2 text-[14px]">
          <button type="button" onClick={() => onJump(i.anchor)} className="shrink-0 font-semibold text-accent-text hover:underline">
            {SECTION_LABEL[i.section] ?? i.section}{i.ref ? ` ${i.ref}` : ` ${i.index + 1}`}
          </button>
          <span className="text-fg-muted">{KIND_LABEL[i.kind] ?? i.kind}{i.unknown_ids?.length ? ` (${i.unknown_ids.join(", ")})` : ""}</span>
          {i.text && <span className="min-w-0 truncate text-fg-strong [overflow-wrap:anywhere]" title={i.text}>— {i.text.length > 110 ? i.text.slice(0, 110) + "…" : i.text}</span>}
        </li>
      ))}
    </ul>
  );
}
