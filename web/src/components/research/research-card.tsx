"use client";

import Link from "next/link";
import { CLASSIFICATION, SEVERITY } from "@/lib/constants";
import { num, relative, utc } from "@/lib/format";
import type { ResearchSummary } from "@/lib/types";
import { useApp, useWsHref } from "../providers";
import { Avatar, Chip, ResultPill, StatusPill } from "../ui/badges";
import { Tooltip } from "../ui/overlay";
import { TacticRail } from "./tactic-rail";

/** Research card (design.md 14.1): severity stripe, whole card is one link, inner chips stay focusable. */
export function ResearchCard({ r }: { r: ResearchSummary }) {
  const wsHref = useWsHref();
  const { activeWorkspace } = useApp();
  const sev = SEVERITY[r.severity] ?? SEVERITY.medium;
  const chips: { key: string; label: string; dot: string; href?: string }[] = [];
  if (r.cves.length) chips.push({ key: "cve", label: r.cves.length > 1 ? `CVE ×${r.cves.length}` : r.cves[0], dot: CLASSIFICATION.cve.color, href: wsHref(`/research?cve=${r.cves[0]}`) });
  if (r.classification.includes("campaign")) chips.push({ key: "camp", label: "Campaign", dot: CLASSIFICATION.campaign.color });
  r.actors.forEach((a) => chips.push({ key: a, label: a, dot: CLASSIFICATION.actor.color, href: wsHref(`/research?actor=${encodeURIComponent(a)}`) }));
  if (r.classification.includes("ttp_trend")) chips.push({ key: "ttp", label: "TTP trend", dot: CLASSIFICATION.ttp.color });
  const visible = chips.slice(0, 3);
  return (
    <article className="group relative flex min-w-0 overflow-hidden rounded-md border border-line bg-surface transition-colors hover:border-line-hover focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-[var(--focus-ring)]">
      <span className="w-1 shrink-0" style={{ background: sev.solid }} aria-hidden />
      <span className="sr-only">Severity: {sev.label}</span>
      <div className="flex min-w-0 flex-1 flex-col gap-3 p-4">
        <div className="flex items-center gap-2">
          <span className="font-mono text-mono-sm text-fg-muted">{r.id}</span>
          <span className="flex-1" />
          <StatusPill status={r.status} />
          <Tooltip content={utc(r.updated_at)}><span className="text-caption text-fg-muted">{relative(r.updated_at)}</span></Tooltip>
        </div>
        <h3 className="line-clamp-2 text-h3 font-semibold">
          <Link href={wsHref(`/research/${r.id}`)} className="after:absolute after:inset-0 focus-visible:outline-none">{r.title}</Link>
        </h3>
        {chips.length > 0 && (
          <div className="relative z-[1] flex flex-wrap gap-1.5">
            {visible.map((c) => <Chip key={c.key} dot={c.dot} href={c.href}>{c.label}</Chip>)}
            {chips.length > 3 && <Chip>+{chips.length - 3}</Chip>}
          </div>
        )}
        <div className="relative z-[1]"><TacticRail tactics={r.rail} variant="mini" /></div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line pt-3">
          {activeWorkspace && (
            <span className="flex items-center gap-1.5 text-caption text-fg-muted">
              {activeWorkspace.name}: {r.result ? <ResultPill status={r.result.status} /> : <span>not in scope</span>}
            </span>
          )}
          <span className="flex-1" />
          <span className="text-caption text-fg-muted tabular">{num(r.cves.length)} CVE{r.cves.length === 1 ? "" : "s"} · {num(r.counts.ttps)} TTPs · {num(r.counts.iocs)} IoCs · {num(r.counts.queries)} queries</span>
          <Avatar initials={r.author?.initials} title={r.author?.name} />
        </div>
      </div>
    </article>
  );
}
