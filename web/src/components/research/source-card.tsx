"use client";

import { ExternalLink, Info, TriangleAlert } from "lucide-react";
import { utc } from "@/lib/format";
import type { Conflict, Source } from "@/lib/types";
import { SourceRating } from "../ui/badges";
import { Toggle } from "../ui/forms";

/** Source card (design.md 18.4). */
export function SourceCard({ s, conflicts, editable, onToggle }:
  { s: Source; conflicts: Conflict[]; editable?: boolean; onToggle?: (included: boolean) => void }) {
  const superseded = conflicts.filter((c) => c.status === "superseded" && c.statements.some((st, i) => st.source_id === s.id && i < c.statements.length - 1)).length;
  return (
    <article id={`source-${s.id}`} className="scroll-mt-28 rounded-md border border-line bg-surface p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-mono-sm text-fg-muted">{s.id}</span>
            <h4 className="text-h4 font-semibold">{s.publisher}</h4>
            {s.type && <span className="text-caption text-fg-muted">{s.type}</span>}
          </div>
          {s.url ? (
            <a href={s.url} target="_blank" rel="noopener noreferrer" className="mt-1 inline-flex max-w-full items-start gap-1 text-[14px] text-accent-text hover:underline">
              <span className="line-clamp-2">{s.title}</span><ExternalLink className="mt-0.5 size-3.5 shrink-0" />
            </a>
          ) : <p className="mt-1 text-[14px]">{s.title}</p>}
        </div>
        <SourceRating reliability={s.reliability} credibility={s.credibility} />
      </div>
      <p className="mt-2 text-caption text-fg-muted">
        Published {s.published ?? "—"} · Updated {s.last_modified ?? "—"} · Fetched {s.last_fetched ? utc(s.last_fetched, false) : "—"}
      </p>
      {s.counts && (
        <p className="mt-1 text-caption text-fg-strong tabular">
          {s.counts.claims} claims used · {s.counts.techniques} techniques · {s.counts.iocs} IoCs · {s.counts.queries} queries
        </p>
      )}
      {s.summary && <p className="mt-2 text-body-sm text-fg-strong">{s.summary}</p>}
      {superseded > 0 && (
        <p className="mt-2 flex items-center gap-1.5 text-body-sm font-semibold" style={{ color: "var(--warning)" }}>
          <TriangleAlert className="size-4" />{superseded} claim{superseded > 1 ? "s" : ""} superseded by a later source
        </p>
      )}
      {s.stale && (
        <div className="mt-3 flex items-start gap-2 rounded-sm border border-info-line bg-info-soft px-3 py-2 text-body-sm">
          <Info className="mt-0.5 size-4 shrink-0 text-info" />This article was updated after it was read. Re-fetch to compare.
        </div>
      )}
      {s.status !== "read" && <p className="mt-2 text-body-sm text-fg-muted">Status: {s.status}</p>}
      {editable && onToggle && (
        <div className="mt-3 border-t border-line pt-3">
          <Toggle checked={s.included} onChange={onToggle} label="Include in synthesis" />
        </div>
      )}
    </article>
  );
}
