"use client";

import clsx from "clsx";
import { ChevronRight, ChevronsDownUp, ChevronsUpDown, Network, PanelRight, Search } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { QUERY_STATUS, QUERY_STATUS_ORDER } from "@/lib/constants";
import { useApp, useWsHref } from "../../providers";
import { QueryStatusPill } from "../../ui/badges";
import { Button, ButtonGroup } from "../../ui/button";
import { Input, Select } from "../../ui/forms";
import { NodeDrawer, nodeColor } from "../tree/details";
import { CLASS_META, branchIds, buildResearchTree, defaultExpanded, descendantCounts, filterTree, findPath, levelCounts, type ClassKey, type TNode } from "../tree/model";
import type { DetailProps } from "./common";

const KIND_CHIP: Record<TNode["kind"], string> = { subject: "Subject", class: "Class", behaviour: "Behaviour", opportunity: "DO", detection: "Detection" };

interface Row { n: TNode; level: number; parent: string | null; setsize: number; posinset: number }

/** List view (spec §7.3): the tree's hierarchy as a nested, expandable ARIA treegrid with counts and filters. */
export function ListTab({ d, canEdit, tacticFilter }: DetailProps & { tacticFilter: string | null }) {
  const { platformName } = useApp();
  const wsHref = useWsHref();
  const rec = d.record;
  const full = useMemo(() => buildResearchTree(d, (p) => platformName(p, true)), [d, platformName]);
  const [cls, setCls] = useState("");
  const [tactic, setTactic] = useState(tacticFilter ?? "");
  const [platform, setPlatform] = useState("");
  const [status, setStatus] = useState("");
  const [text, setText] = useState("");
  const [open, setOpen] = useState<Set<string>>(() => defaultExpanded(full));
  const [focus, setFocus] = useState("root");
  const [selected, setSelected] = useState<string | null>(null);
  const grid = useRef<HTMLDivElement | null>(null);

  useEffect(() => { if (tacticFilter !== null) setTactic(tacticFilter); }, [tacticFilter]);

  const filters = { cls, tactic, platform, status, text };
  const filtering = !!(tactic || platform || status || text.trim());
  const root = useMemo(() => filterTree(full, { cls, tactic, platform, status, text }), [full, cls, tactic, platform, status, text]);
  // A filter that looks below level 3 opens every matching branch so the matches are visible.
  useEffect(() => { setOpen(filtering ? new Set(branchIds(root)) : defaultExpanded(root)); }, [root, filtering]);

  const counts = useMemo(() => levelCounts(root), [root]);
  const rows = useMemo(() => {
    const out: Row[] = [];
    const walk = (n: TNode, level: number, parent: string | null, setsize: number, posinset: number) => {
      out.push({ n, level, parent, setsize, posinset });
      if (open.has(n.id)) n.children.forEach((c, i) => walk(c, level + 1, n.id, n.children.length, i + 1));
    };
    walk(root, 0, null, 1, 1);
    return out;
  }, [root, open]);

  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const focusRow = (id: string) => {
    setFocus(id);
    requestAnimationFrame(() => grid.current?.querySelector<HTMLElement>(`[data-row="${CSS.escape(id)}"]`)?.focus());
  };
  const onKey = (e: React.KeyboardEvent, r: Row, i: number) => {
    const has = r.n.children.length > 0;
    if (e.key === "ArrowDown" && rows[i + 1]) focusRow(rows[i + 1].n.id);
    else if (e.key === "ArrowUp" && rows[i - 1]) focusRow(rows[i - 1].n.id);
    else if (e.key === "ArrowRight") { if (has && !open.has(r.n.id)) toggle(r.n.id); else if (has) focusRow(r.n.children[0].id); }
    else if (e.key === "ArrowLeft") { if (has && open.has(r.n.id)) toggle(r.n.id); else if (r.parent) focusRow(r.parent); }
    else if (e.key === "Home") focusRow(rows[0].n.id);
    else if (e.key === "End") focusRow(rows[rows.length - 1].n.id);
    else if (e.key === " ") { if (has) toggle(r.n.id); }
    else if (e.key === "Enter") setSelected(r.n.id);
    else return;
    e.preventDefault();
  };

  const tactics = Array.from(new Map(rec.mitre.map((m) => [m.tactic_id, m.tactic])).entries());
  const platforms = Array.from(new Set(rec.hunts.queries.map((q) => q.platform)));
  const statuses = QUERY_STATUS_ORDER.filter((s) => rec.hunts.queries.some((q) => q.status === s));
  const selNode = selected ? findPath(root, selected) : [];
  const sel = selNode[selNode.length - 1] ?? null;
  const clear = () => { setCls(""); setTactic(""); setPlatform(""); setStatus(""); setText(""); };
  const anyFilter = Object.values(filters).some(Boolean);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ButtonGroup>
          <Button size="sm" icon={<ChevronsUpDown />} onClick={() => setOpen(new Set(branchIds(root)))}>Expand all</Button>
          <Button size="sm" icon={<ChevronsDownUp />} onClick={() => setOpen(defaultExpanded(root))}>Collapse to level 3</Button>
        </ButtonGroup>
        <Input inputSize="sm" className="w-full sm:w-56" prefixIcon={<Search />} placeholder="Filter by text" value={text} onChange={(e) => setText(e.target.value)} aria-label="Filter rows by text" />
        <Link href={wsHref("?tab=tree")} className="ml-auto inline-flex h-7 items-center gap-1.5 rounded-sm px-2 text-[13px] font-semibold text-accent-text hover:bg-accent-soft"><Network className="size-4" />Tree view</Link>
      </div>
      <div className="mb-3 grid grid-cols-2 gap-2 sm:flex sm:flex-wrap">
        <Select size="sm" className="sm:w-44" value={cls} onChange={setCls} ariaLabel="Filter by classification"
          options={[{ value: "", label: "All classifications" }, ...full.children.map((c) => ({ value: c.cls, label: CLASS_META[c.cls as ClassKey]?.label ?? c.label }))]} />
        <Select size="sm" className="sm:w-48" value={tactic} onChange={setTactic} ariaLabel="Filter by tactic"
          options={[{ value: "", label: "All tactics" }, ...tactics.map(([id, name]) => ({ value: id, label: name }))]} />
        <Select size="sm" className="sm:w-44" value={platform} onChange={setPlatform} ariaLabel="Filter by platform"
          options={[{ value: "", label: "All platforms" }, ...platforms.map((p) => ({ value: p, label: platformName(p) }))]} />
        <Select size="sm" className="sm:w-44" value={status} onChange={setStatus} ariaLabel="Filter by detection status"
          options={[{ value: "", label: "Any detection status" }, ...statuses.map((s) => ({ value: s, label: QUERY_STATUS[s]?.label ?? s }))]} />
        {anyFilter && <Button size="sm" variant="tertiary" onClick={clear}>Clear filters</Button>}
      </div>
      <p className="mb-2 text-caption text-fg-muted tabular" aria-live="polite">
        {counts.classes} classifications · {counts.behaviours} attack behaviours · {counts.opportunities} detection opportunities · {counts.detections} detections
      </p>

      <div ref={grid} role="treegrid" aria-label="Research hierarchy" aria-readonly className="overflow-hidden rounded-md border border-line bg-surface">
        <div role="row" className="hidden border-b border-line bg-subtle px-3 py-1.5 text-caption font-semibold text-fg-muted sm:flex">
          <span role="columnheader" className="flex-1">Name</span>
          <span role="columnheader" className="w-60 text-right">Below this level</span>
          <span role="columnheader" className="w-24 text-right"><span className="sr-only">Details</span></span>
        </div>
        {rows.map((r, i) => {
          const n = r.n;
          const has = n.children.length > 0;
          const isOpen = open.has(n.id);
          const c = has ? descendantCounts(n) : null;
          const q = n.ref.t === "query" ? n.ref.query : null;
          return (
            <div key={n.id} role="row" data-row={n.id} aria-level={r.level + 1} aria-setsize={r.setsize} aria-posinset={r.posinset}
              aria-expanded={has ? isOpen : undefined} aria-selected={selected === n.id} tabIndex={focus === n.id ? 0 : -1}
              onKeyDown={(e) => onKey(e, r, i)} onFocus={() => setFocus(n.id)}
              className={clsx("flex flex-wrap items-start gap-x-2 gap-y-1 border-b border-line py-2 pr-3 last:border-0 outline-none hover:bg-[var(--g-25)] focus-visible:bg-accent-soft dark:hover:bg-subtle",
                n.kind === "class" && "bg-[var(--g-25)] dark:bg-subtle")}
              style={{ paddingLeft: 8 + Math.min(r.level, 4) * 18 }}>
              <div role="gridcell" className="flex min-w-0 flex-[1_1_16rem] items-start gap-2">
                {has ? (
                  <button tabIndex={-1} onClick={() => { toggle(n.id); setFocus(n.id); }} aria-label={isOpen ? `Collapse ${n.label}` : `Expand ${n.label}`}
                    className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-sm text-fg-muted hover:bg-subtle">
                    <ChevronRight className={clsx("size-4 transition-transform duration-[var(--motion-base)]", isOpen && "rotate-90")} />
                  </button>
                ) : <span className="w-5 shrink-0" />}
                <span className="mt-0.5 inline-flex h-5 shrink-0 items-center gap-1.5 rounded-sm bg-chip px-1.5 text-[11px] font-semibold text-chip-fg">
                  <span className="size-1.5 rounded-full" style={{ background: nodeColor(n) }} />{KIND_CHIP[n.kind]}
                </span>
                <div className="min-w-0 flex-1">
                  <button tabIndex={-1} onClick={() => { if (has) toggle(n.id); else setSelected(n.id); setFocus(n.id); }}
                    className={clsx("text-left text-[14px] break-words [overflow-wrap:anywhere] hover:underline", n.kind === "class" && "font-semibold", n.kind === "subject" && "font-semibold")}>
                    {n.tag && n.kind === "behaviour" && <span className="mr-1.5 font-mono text-mono-sm text-accent-text">{n.tag}</span>}
                    {n.kind === "opportunity" && n.sub && <span className="mr-1.5 font-mono text-mono-sm font-semibold" style={{ color: "var(--cls-opportunity)" }}>{n.sub}</span>}
                    {n.label}
                  </button>
                  <div className="text-caption text-fg-muted break-words [overflow-wrap:anywhere]">
                    {n.kind === "class" && n.sub}
                    {n.kind === "subject" && n.sub}
                    {n.kind === "behaviour" && [n.sub, n.context].filter(Boolean).join(" · ")}
                    {n.kind === "opportunity" && (n.ref.t === "opp" ? n.ref.opp.logic : n.ref.t === "group" ? `${n.ref.group.queries.length} platform queries` : "")}
                    {q && q.title}
                  </div>
                </div>
              </div>
              <div role="gridcell" className="flex min-w-0 items-center gap-2 pl-7 text-caption text-fg-muted tabular sm:w-60 sm:justify-end sm:pl-0">
                {c && [n.kind === "subject" || n.kind === "class" ? `${c.behaviours} beh.` : "", n.kind !== "opportunity" ? `${c.opportunities} DO` : "", `${c.detections} det.`].filter(Boolean).join(" · ")}
                {!has && n.kind === "behaviour" && <span className="text-fg-faint">No detection yet</span>}
                {q && <QueryStatusPill status={q.status} />}
              </div>
              <div role="gridcell" className="flex w-auto justify-end sm:w-24">
                <Button size="sm" variant="tertiary" icon={<PanelRight />} tabIndex={-1} onClick={() => { setSelected(n.id); setFocus(n.id); }} aria-label={`Details: ${n.label}`}>
                  {q ? "Query" : "Details"}
                </Button>
              </div>
            </div>
          );
        })}
        {root.children.length === 0 && <p className="p-6 text-center text-fg-muted">Nothing matches these filters.</p>}
      </div>

      <NodeDrawer node={sel} siblings={selNode[selNode.length - 2]?.children ?? []} rec={rec} canEdit={canEdit}
        onSelect={(n) => setSelected(n.id)} onClose={() => { setSelected(null); if (focus) focusRow(focus); }} />
    </div>
  );
}
