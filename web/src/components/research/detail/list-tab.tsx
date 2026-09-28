"use client";

import clsx from "clsx";
import { ChevronRight, ChevronsDownUp, ChevronsUpDown } from "lucide-react";
import { useMemo, useState } from "react";
import { CLASSIFICATION } from "@/lib/constants";
import { useApp } from "../../providers";
import { QueryStatusPill } from "../../ui/badges";
import { Button, ButtonGroup } from "../../ui/button";
import { Select } from "../../ui/forms";
import type { DetailProps } from "./common";

interface Row { id: string; level: number; kind: "ttp" | "behaviour" | "opportunity" | "detection"; label: React.ReactNode; meta?: React.ReactNode; right?: React.ReactNode; parent?: string; hasKids: boolean; tactic?: string }

/** Expandable list view: the non-visual equivalent of the tree (design.md 15.5). */
export function ListTab({ d, tacticFilter }: DetailProps & { tacticFilter: string | null }) {
  const { platformName } = useApp();
  const rec = d.record;
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [tactic, setTactic] = useState<string>(tacticFilter ?? "");

  const rows = useMemo(() => {
    const out: Row[] = [];
    const steps = rec.attack_paths.flatMap((p) => p.steps);
    const seen = new Set<string>();
    for (const m of rec.mitre) {
      if (seen.has(m.technique_id)) continue;
      seen.add(m.technique_id);
      if (tactic && m.tactic_id !== tactic) continue;
      const bs = steps.filter((s) => s.technique_id === m.technique_id);
      const opps = rec.detection_opportunities.filter((o) => bs.some((b) => b.ref === o.behaviour_ref) || (!bs.length && o.techniques.includes(m.technique_id)));
      const nDet = opps.reduce((a, o) => a + rec.hunts.queries.filter((q) => q.opportunity_id === o.id).length, 0);
      const tid = `t-${m.technique_id}`;
      out.push({ id: tid, level: 0, kind: "ttp", hasKids: bs.length > 0, tactic: m.tactic_id,
        label: <><span className="font-mono text-mono text-accent-text">{m.technique_id}</span> <span>{m.sub_technique || m.technique}</span></>,
        meta: `${m.tactic} · ${bs.length} behaviour${bs.length === 1 ? "" : "s"} · ${nDet} detection${nDet === 1 ? "" : "s"}` });
      for (const b of bs) {
        const bo = rec.detection_opportunities.filter((o) => o.behaviour_ref === b.ref);
        const bid = `${tid}/b-${b.ref}`;
        out.push({ id: bid, parent: tid, level: 1, kind: "behaviour", hasKids: bo.length > 0, label: b.behaviour,
          meta: `${bo.length} detection opportunit${bo.length === 1 ? "y" : "ies"}`, right: <span className="font-mono text-mono-sm text-fg-muted">{b.ref}</span> });
        for (const o of bo) {
          const qs = rec.hunts.queries.filter((q) => q.opportunity_id === o.id);
          const oid = `${bid}/o-${o.id}`;
          out.push({ id: oid, parent: bid, level: 2, kind: "opportunity", hasKids: qs.length > 0,
            label: <><span className="font-mono text-mono-sm font-semibold" style={{ color: "var(--cls-opportunity)" }}>{o.id}</span> {o.title}</>,
            meta: o.logic });
          out.push({ id: `${oid}/q`, parent: oid, level: 3, kind: "detection", hasKids: false,
            label: <span className="flex flex-wrap items-center gap-x-2">{qs.map((q, i) => <span key={q.id}>{i > 0 && <span className="text-fg-faint">· </span>}{platformName(q.platform, true)}</span>)}</span>,
            right: qs.length ? <QueryStatusPill status={qs.find((q) => q.platform !== "sigma")?.status ?? qs[0].status} /> : null });
        }
      }
    }
    return out;
  }, [rec, tactic, platformName]);

  const visible = rows.filter((r) => {
    let p = r.parent;
    while (p) {
      if (!open.has(p)) return false;
      p = rows.find((x) => x.id === p)?.parent;
    }
    return true;
  });
  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const kindLabel = { ttp: ["TTP", CLASSIFICATION.ttp.color], behaviour: ["Behaviour", CLASSIFICATION.behaviour.color], opportunity: ["DO", CLASSIFICATION.opportunity.color], detection: ["Detections", CLASSIFICATION.detection.color] } as const;
  const tactics = Array.from(new Map(rec.mitre.map((m) => [m.tactic_id, m.tactic])).entries());

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ButtonGroup>
          <Button size="sm" icon={<ChevronsUpDown />} onClick={() => setOpen(new Set(rows.filter((r) => r.hasKids).map((r) => r.id)))}>Expand all</Button>
          <Button size="sm" icon={<ChevronsDownUp />} onClick={() => setOpen(new Set())}>Collapse all</Button>
        </ButtonGroup>
        <Select size="sm" className="w-56" value={tactic} onChange={setTactic} ariaLabel="Filter by tactic"
          options={[{ value: "", label: "All tactics" }, ...tactics.map(([id, name]) => ({ value: id, label: name }))]} />
        <span className="ml-auto text-caption text-fg-muted">{rows.filter((r) => r.kind === "ttp").length} techniques · {rec.detection_opportunities.length} detection opportunities · {rec.hunts.queries.length} queries</span>
      </div>
      <div role="treegrid" aria-label="Research hierarchy" className="overflow-hidden rounded-md border border-line bg-surface">
        {visible.map((r) => (
          <div key={r.id} role="row" aria-level={r.level + 1} aria-expanded={r.hasKids ? open.has(r.id) : undefined}
            className="flex min-h-9 items-start gap-2 border-b border-line py-2 pr-4 last:border-0 hover:bg-[var(--g-25)] dark:hover:bg-subtle"
            style={{ paddingLeft: 12 + r.level * 20 }}>
            {r.level > 0 && <span className="-ml-3 w-px self-stretch bg-[var(--border-subtle)]" aria-hidden />}
            {r.hasKids ? (
              <button onClick={() => toggle(r.id)} aria-label={open.has(r.id) ? "Collapse" : "Expand"}
                onKeyDown={(e) => { if (e.key === "ArrowRight" && !open.has(r.id)) toggle(r.id); if (e.key === "ArrowLeft" && open.has(r.id)) toggle(r.id); }}
                className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-sm text-fg-muted hover:bg-subtle">
                <ChevronRight className={clsx("size-4 transition-transform duration-[var(--motion-base)]", open.has(r.id) && "rotate-90")} />
              </button>
            ) : <span className="w-5 shrink-0" />}
            <span className="mt-0.5 inline-flex h-5 shrink-0 items-center gap-1.5 rounded-sm bg-chip px-1.5 text-[11px] font-semibold text-chip-fg">
              <span className="size-1.5 rounded-full" style={{ background: kindLabel[r.kind][1] }} />{kindLabel[r.kind][0]}
            </span>
            <div className="min-w-0 flex-1">
              <div className={clsx("text-[14px]", r.kind === "behaviour" && "font-mono text-mono")}>{r.label}</div>
              {r.meta && <div className="text-caption text-fg-muted">{r.meta}</div>}
            </div>
            {r.right}
          </div>
        ))}
        {!visible.length && <p className="p-6 text-center text-fg-muted">No techniques mapped{tactic ? " for this tactic" : ""}.</p>}
      </div>
    </div>
  );
}
