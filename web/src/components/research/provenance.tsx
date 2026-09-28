"use client";

import { ExternalLink } from "lucide-react";
import Link from "next/link";
import { PROVENANCE, QUERY_STATUS_ORDER } from "@/lib/constants";
import { refang } from "@/lib/format";
import type { Provenance, ProvenanceItem, Query, ResearchRecord, Source } from "@/lib/types";
import { Badge } from "../ui/badges";
import { Tooltip } from "../ui/overlay";

/** One detection: every platform variant (Sigma, SPL, KQL…) of the same logic. */
export interface DetectionGroup {
  key: string; title: string; type: Query["type"]; opportunityId: string | null; queries: Query[]; platforms: string[];
  provenance: Provenance; sourceIds: string[]; status: string; mixedStatus: boolean;
}

export const sourceIndex = (rec: ResearchRecord): Record<string, Source> => Object.fromEntries(rec.sources.map((s) => [s.id, s]));

/** Group key: backend `group`, else the opportunity, else the title (so the old data shape still collapses to one node per detection). */
export const groupKey = (q: Query) => q.group || q.opportunity_id || (q.origin === "reference" ? `ref:${q.id}` : `${q.type}:${q.title}`);

export function inferProvenance(q: Query): Provenance {
  if (q.provenance) return q.provenance;
  if (q.origin === "reference") return "vendor";
  if (q.opportunity_id || q.type === "ioc" || q.type === "vuln") return "derived";
  return "generic";
}

const uniq = <T,>(xs: T[]) => Array.from(new Set(xs));

/** Sources behind a query: backend `source_ids`, else inferred from its opportunity → behaviour, its indicators or its CVEs. */
export function querySourceIds(q: Query, rec: ResearchRecord): string[] {
  if (q.source_ids) return q.source_ids;
  if (q.opportunity_id) {
    const o = rec.detection_opportunities.find((x) => x.id === q.opportunity_id);
    if (o?.source_ids?.length) return o.source_ids;
    if (o) {
      const step = rec.attack_paths.flatMap((p) => p.steps).find((s) => s.ref === o.behaviour_ref);
      const ioa = rec.ioas?.find((i) => i.id === o.behaviour_ref);
      return uniq([...(step?.source_ids ?? []), ...(ioa?.source_ids ?? [])]);
    }
  }
  if (q.type === "ioc") {
    const body = q.body.toLowerCase();
    return uniq(rec.iocs.filter((i) => body.includes(refang(i.value).toLowerCase())).flatMap((i) => i.source_ids));
  }
  if (q.type === "vuln") {
    const text = `${q.title} ${q.body}`;
    return uniq(rec.vulnerabilities.filter((v) => text.includes(v.cve)).flatMap((v) => v.source_ids));
  }
  return [];
}

export function groupQueries(rec: ResearchRecord): DetectionGroup[] {
  const map = new Map<string, Query[]>();
  for (const q of rec.hunts?.queries ?? []) map.set(groupKey(q), [...(map.get(groupKey(q)) ?? []), q]);
  return Array.from(map.entries()).map(([key, qs]) => {
    const sorted = [...qs].sort((a, b) => (a.platform === "sigma" ? 1 : 0) - (b.platform === "sigma" ? 1 : 0));
    const head = sorted[0];
    const statuses = uniq(sorted.filter((q) => q.platform !== "sigma").map((q) => q.status));
    const rank = (s: string) => { const i = QUERY_STATUS_ORDER.indexOf(s); return i < 0 ? 99 : i; };
    const status = (statuses.length ? statuses : [head.status]).sort((a, b) => rank(a) - rank(b))[0];
    const opp = rec.detection_opportunities.find((o) => o.id === head.opportunity_id);
    return {
      key, title: opp?.title ?? head.title, type: head.type, opportunityId: head.opportunity_id, queries: sorted,
      platforms: uniq(sorted.map((q) => q.platform)), provenance: inferProvenance(head),
      sourceIds: uniq(sorted.flatMap((q) => querySourceIds(q, rec))), status, mixedStatus: statuses.length > 1,
    };
  });
}

export function ProvenanceBadge({ provenance }: { provenance: Provenance }) {
  const p = PROVENANCE[provenance] ?? PROVENANCE.derived;
  return <Badge tone={p.tone} title={p.help}>{p.label}</Badge>;
}

/** Publisher chips for a list of source IDs; each links to its card on the Sources tab, with the article one click away. */
export function SourceChips({ ids, sources, label = "From", empty, compact }: { ids: string[]; sources: Record<string, Source>; label?: string; empty?: React.ReactNode; compact?: boolean }) {
  if (!ids.length) return empty ? <span className="text-caption text-fg-muted">{empty}</span> : null;
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-1">
      {label && <span className="mr-0.5 text-caption text-fg-muted">{label}</span>}
      {ids.map((id) => {
        const s = sources[id];
        return (
          <span key={id} className={`inline-flex h-6 min-w-0 items-center overflow-hidden rounded-sm bg-chip text-[12px] font-medium text-chip-fg ${compact ? "max-w-[150px]" : "max-w-[240px]"}`}>
            <Tooltip content={s ? `${s.publisher} — ${s.title}` : `Source ${id}`}>
              <Link href={`?tab=sources#source-${id}`} className="flex min-w-0 items-center gap-1 px-1.5 hover:bg-[var(--g-100)] dark:hover:bg-[#2E3440]">
                <span className="font-mono text-[11px] text-fg-muted">{id}</span>
                <span className="truncate">{s?.publisher ?? "Unknown source"}</span>
              </Link>
            </Tooltip>
            {s?.url && !compact && (
              <a href={s.url} target="_blank" rel="noopener noreferrer" aria-label={`Open ${s.publisher} article`}
                className="grid h-full w-5 shrink-0 place-items-center border-l border-[var(--border-subtle)] text-fg-muted hover:bg-[var(--g-100)] hover:text-fg dark:hover:bg-[#2E3440]">
                <ExternalLink className="size-3" />
              </a>
            )}
          </span>
        );
      })}
    </span>
  );
}

/** Library profile panel: research → source → quote, grouped by research. Renders nothing when the API has no provenance yet. */
export function SourceTrail({ items, wsHref, total }: { items?: ProvenanceItem[] | null; wsHref: (p: string) => string; total?: number }) {
  if (!items?.length) return null;
  const byResearch = new Map<string, ProvenanceItem[]>();
  for (const it of items) byResearch.set(it.research_id, [...(byResearch.get(it.research_id) ?? []), it]);
  const publishers = uniq(items.map((i) => i.publisher).filter(Boolean));
  return (
    <section aria-labelledby="source-trail" className="rounded-md border border-line bg-surface">
      <header className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-line px-4 py-3">
        <h2 id="source-trail" className="text-h3 font-semibold">Source trail</h2>
        <span className="text-caption text-fg-muted">{total && total > items.length ? `Showing ${items.length} of ${total} citations` : `${items.length} citation${items.length === 1 ? "" : "s"}`} · {publishers.length} publisher{publishers.length === 1 ? "" : "s"} · {byResearch.size} research record{byResearch.size === 1 ? "" : "s"}</span>
      </header>
      <ol className="divide-y divide-[var(--border-subtle)]">
        {Array.from(byResearch.entries()).map(([rid, its]) => (
          <li key={rid} className="px-4 py-3">
            <Link href={wsHref(`/research/${rid}?tab=sources`)} className="flex min-w-0 flex-wrap items-baseline gap-x-2 hover:underline">
              <span className="font-mono text-mono-sm text-accent-text">{rid}</span>
              {its[0].research_title && <span className="min-w-0 text-[14px] font-semibold break-words">{its[0].research_title}</span>}
            </Link>
            <ul className="mt-2 space-y-2 border-l-2 border-line pl-3">
              {its.map((it, i) => (
                <li key={`${it.source_id}-${i}`} className="min-w-0 text-[14px]">
                  <div className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                    <span className="font-mono text-[11px] text-fg-muted">{it.source_id}</span>
                    <span className="font-semibold">{it.publisher ?? "Unknown publisher"}</span>
                    {it.url ? (
                      <a href={it.url} target="_blank" rel="noopener noreferrer" className="inline-flex min-w-0 items-baseline gap-1 text-accent-text hover:underline break-words [overflow-wrap:anywhere]">
                        {it.title || it.url}<ExternalLink className="size-3 shrink-0 self-center" />
                      </a>
                    ) : it.title ? <span className="text-fg-muted break-words">{it.title}</span> : null}
                  </div>
                  {it.quote && <p className="mt-1 italic text-fg-strong break-words">“{it.quote}”</p>}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** DOM-safe anchor for a detection card on the Hunts tab. */
export const groupAnchor = (key: string) => `det-${key.replace(/[^A-Za-z0-9_-]+/g, "-")}`;
