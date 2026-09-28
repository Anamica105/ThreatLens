"use client";

import { ChevronDown, TriangleAlert } from "lucide-react";
import type { Conflict, Source } from "@/lib/types";
import { Menu } from "../ui/overlay";

const LABEL = { confirmed: "Confirmed", disputed: "Disputed", superseded: "Superseded" } as const;

/** Claim conflict callout (design.md 18.5). Disputed claims block publishing. */
export function ClaimConflict({ c, sources, onStatus }: { c: Conflict; sources: Record<string, Source>; onStatus?: (s: Conflict["status"]) => void }) {
  return (
    <div className="rounded-md border p-4" style={{ background: "var(--warning-soft)", borderColor: "var(--warning-border)" }} role="note">
      <div className="flex items-center gap-2 text-h4 font-semibold" style={{ color: "var(--warning)" }}>
        <TriangleAlert className="size-5" /> Sources disagree
        <span className="font-normal text-fg">· {c.topic}</span>
      </div>
      <ul className="mt-2 space-y-1.5">
        {c.statements.map((s, i) => (
          <li key={i} className="text-[14px] text-fg">
            <a href={`#source-${s.source_id}`} className="font-semibold hover:underline">{sources[s.source_id]?.publisher ?? s.source_id}</a>
            <span className="text-fg-muted"> ({s.date})</span>: {s.text}
          </li>
        ))}
      </ul>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-[14px]"><span className="font-semibold">Status: {LABEL[c.status]}</span>{c.resolution ? ` — ${c.resolution}` : ""}</p>
        {onStatus && (
          <Menu width={180} items={(Object.keys(LABEL) as Conflict["status"][]).map((k) => ({ label: LABEL[k], onSelect: () => onStatus(k), shortcut: c.status === k ? "✓" : "" }))}
            trigger={(p) => (
              <button {...p} className="inline-flex h-7 items-center gap-1 rounded-sm border border-line-strong bg-surface px-2.5 text-[13px] font-semibold hover:bg-subtle">
                Change status <ChevronDown className="size-4" />
              </button>
            )} />
        )}
      </div>
    </div>
  );
}
