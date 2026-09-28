"use client";

import { hierarchy, tree as d3tree, type HierarchyPointNode } from "d3-hierarchy";
import { ChevronsDownUp, ChevronsUpDown, Download, List, Map as MapIcon, Maximize, Minus, Plus, Search } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CLASSIFICATION, DATA_SOURCES, QUERY_STATUS } from "@/lib/constants";
import type { Query, ResearchRecord } from "@/lib/types";
import { useApp } from "../../providers";
import { AttackChip, Badge, Chip } from "../../ui/badges";
import { Button, ButtonGroup } from "../../ui/button";
import { Input } from "../../ui/forms";
import { Drawer, Menu, Tooltip } from "../../ui/overlay";
import { QueryBlock } from "../query-block";
import { Quote, SourceRefs, type DetailProps } from "./common";

type Kind = "subject" | "class" | "behaviour" | "opportunity" | "detection" | "entity";
export interface TNode {
  id: string; kind: Kind; label: string; sub?: string; cls?: string; children?: TNode[]; data?: Record<string, unknown>;
  techId?: string; evidence?: number; sources?: string[];
}

const SIZE: Record<Kind, { w: number; h: number }> = {
  subject: { w: 260, h: 64 }, class: { w: 220, h: 44 }, behaviour: { w: 260, h: 64 }, entity: { w: 260, h: 44 },
  opportunity: { w: 240, h: 64 }, detection: { w: 140, h: 32 },
};
const COL_X = [0, 324, 608, 932, 1236];

export function buildTree(id: string, rec: ResearchRecord, platformShort: (p: string) => string): TNode {
  const queries = rec.hunts?.queries ?? [];
  const oppsFor = (ref: string) => rec.detection_opportunities.filter((o) => o.behaviour_ref === ref);
  const oppNode = (o: ResearchRecord["detection_opportunities"][number]): TNode => ({
    id: `do-${o.id}`, kind: "opportunity", label: o.title, sub: o.id, cls: "opportunity", data: o as unknown as Record<string, unknown>,
    children: queries.filter((q) => q.opportunity_id === o.id).map((q) => ({ id: `q-${q.id}`, kind: "detection", label: platformShort(q.platform), sub: q.status, cls: "detection", data: q as unknown as Record<string, unknown> })),
  });
  const stepNode = (s: ResearchRecord["attack_paths"][number]["steps"][number]): TNode => ({
    id: `b-${s.ref}`, kind: "behaviour", label: s.behaviour, sub: s.ref, cls: "behaviour", techId: s.technique_id, sources: s.source_ids,
    data: s as unknown as Record<string, unknown>, evidence: rec.mitre.filter((m) => m.technique_id === s.technique_id).length, children: oppsFor(s.ref).map(oppNode),
  });
  const kids: TNode[] = [];
  if (rec.vulnerabilities.length) kids.push({
    id: "c-cve", kind: "class", label: "CVE", sub: `×${rec.vulnerabilities.length}`, cls: "cve",
    children: rec.vulnerabilities.map((v) => ({ id: `cve-${v.cve}`, kind: "entity", label: v.cve, sub: v.cvss ? `CVSS ${v.cvss}` : "", cls: "cve", sources: v.source_ids, data: v as unknown as Record<string, unknown> })),
  });
  if (rec.classification.includes("campaign") && rec.attack_paths.length) kids.push({
    id: "c-campaign", kind: "class", label: "Campaign", sub: `${rec.attack_paths.length} paths`, cls: "campaign",
    children: rec.attack_paths.map((p) => ({ id: `ap-${p.id}`, kind: "entity", label: p.name, sub: p.id, cls: "campaign", data: p as unknown as Record<string, unknown> })),
  });
  if (rec.threat_actors.length) kids.push({
    id: "c-actor", kind: "class", label: "Threat actors", sub: `×${rec.threat_actors.length}`, cls: "actor",
    children: rec.threat_actors.map((a) => ({ id: `actor-${a.name}`, kind: "entity", label: a.name, sub: a.aliases.join(", "), cls: "actor", sources: a.source_ids, data: a as unknown as Record<string, unknown> })),
  });
  if (rec.malware_tools.length) kids.push({
    id: "c-intel", kind: "class", label: "Threat intel", sub: `×${rec.malware_tools.length}`, cls: "intel",
    children: rec.malware_tools.map((m) => ({ id: `mal-${m.name}`, kind: "entity", label: m.name, sub: m.type, cls: "intel", sources: m.source_ids, data: m as unknown as Record<string, unknown> })),
  });
  const steps = rec.attack_paths.flatMap((p) => p.steps);
  const unmatched = rec.detection_opportunities.filter((o) => !steps.some((s) => s.ref === o.behaviour_ref));
  kids.push({
    id: "c-ttp", kind: "class", label: "TTPs", sub: `×${new Set(rec.mitre.map((m) => m.technique_id)).size}`, cls: "ttp",
    children: [...steps.map(stepNode), ...unmatched.map(oppNode)],
  });
  return { id: "root", kind: "subject", label: rec.title.split(":")[0] || rec.title, sub: id, cls: "subject", children: kids };
}

function wrap(text: string, width: number, lines: number, px = 7.2): string[] {
  const max = Math.floor(width / px);
  const words = text.split(/\s+/);
  const out: string[] = [];
  let cur = "";
  for (const w of words) {
    if ((cur + " " + w).trim().length > max) {
      if (cur) out.push(cur);
      cur = w.length > max ? w.slice(0, max - 1) + "…" : w;
      if (out.length === lines) break;
    } else cur = (cur + " " + w).trim();
  }
  if (out.length < lines && cur) out.push(cur);
  if (out.length === lines && words.join(" ").length > out.join(" ").length) out[lines - 1] = out[lines - 1].replace(/.{0,1}$/, "…");
  return out.slice(0, lines);
}

type PNode = HierarchyPointNode<TNode>;

export function TreeTab({ d, canEdit }: DetailProps) {
  const { platformName } = useApp();
  const rec = d.record;
  const root = useMemo(() => buildTree(d.id, rec, (p) => platformName(p, true)), [d.id, rec, platformName]);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(["root", "c-cve", "c-campaign", "c-actor", "c-intel", "c-ttp"]));
  const [selected, setSelected] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string>("root");
  const [q, setQ] = useState("");
  const [matchIdx, setMatchIdx] = useState(0);
  const [minimap, setMinimap] = useState(true);
  const [view, setView] = useState({ x: 40, y: 0, k: 0.85 });
  const box = useRef<HTMLDivElement | null>(null);
  const svg = useRef<SVGSVGElement | null>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);

  const all = useMemo(() => {
    const ids: string[] = [];
    const walk = (n: TNode) => { if (n.children?.length) ids.push(n.id); n.children?.forEach(walk); };
    walk(root);
    return ids;
  }, [root]);

  const layout = useMemo(() => {
    const h = hierarchy<TNode>(root, (n) => (expanded.has(n.id) ? n.children : undefined));
    const t = d3tree<TNode>().nodeSize([1, 1]).separation((a, b) => (SIZE[a.data.kind].h + SIZE[b.data.kind].h) / 2 + 12);
    const laid = t(h);
    const nodes = laid.descendants();
    const minY = Math.min(...nodes.map((n) => n.x - SIZE[n.data.kind].h / 2));
    const maxY = Math.max(...nodes.map((n) => n.x + SIZE[n.data.kind].h / 2));
    return { nodes, links: laid.links(), minY, maxY, width: COL_X[Math.max(...nodes.map((n) => n.depth))] + 300 };
  }, [root, expanded]);

  const byId = useMemo(() => new Map(layout.nodes.map((n) => [n.data.id, n])), [layout]);
  const pathIds = useMemo(() => {
    if (!selected) return null;
    const n = byId.get(selected);
    if (!n) return null;
    const s = new Set<string>();
    n.ancestors().forEach((a) => s.add(a.data.id));
    n.descendants().forEach((c) => s.add(c.data.id));
    return s;
  }, [selected, byId]);

  const matches = useMemo(() => {
    if (!q.trim()) return [] as string[];
    const ql = q.toLowerCase();
    const out: string[] = [];
    const walk = (n: TNode) => { if ((n.label + " " + (n.sub ?? "") + " " + (n.techId ?? "")).toLowerCase().includes(ql)) out.push(n.id); n.children?.forEach(walk); };
    walk(root);
    return out;
  }, [q, root]);

  const reveal = useCallback((id: string) => {
    const parents: string[] = [];
    const find = (n: TNode, trail: string[]): boolean => {
      if (n.id === id) { parents.push(...trail); return true; }
      return (n.children ?? []).some((c) => find(c, [...trail, n.id]));
    };
    find(root, []);
    setExpanded((e) => new Set([...e, ...parents]));
  }, [root]);

  const centerOn = useCallback((id: string) => {
    requestAnimationFrame(() => {
      const n = byId.get(id);
      const el = box.current;
      if (!n || !el) return;
      setView((v) => ({ ...v, x: el.clientWidth / 2 - (COL_X[n.depth] + SIZE[n.data.kind].w / 2) * v.k, y: el.clientHeight / 2 - n.x * v.k }));
    });
  }, [byId]);

  useEffect(() => {
    if (!matches.length) return;
    const id = matches[matchIdx % matches.length];
    reveal(id);
    centerOn(id);
  }, [matches, matchIdx, reveal, centerOn]);

  const fit = useCallback(() => {
    const el = box.current;
    if (!el) return;
    const h = layout.maxY - layout.minY + 40;
    const k = Math.min(1.2, Math.max(0.2, Math.min((el.clientWidth - 40) / layout.width, (el.clientHeight - 40) / h)));
    setView({ k, x: 20, y: el.clientHeight / 2 - ((layout.minY + layout.maxY) / 2) * k });
  }, [layout]);

  useEffect(() => { fit(); /* initial */ }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const zoom = (f: number) => setView((v) => {
    const el = box.current!;
    const cx = el.clientWidth / 2, cy = el.clientHeight / 2;
    const k = Math.min(2.5, Math.max(0.2, v.k * f));
    return { k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k };
  });

  const onWheel = (e: React.WheelEvent) => {
    if (!e.ctrlKey && !e.metaKey && Math.abs(e.deltaY) < 50 && !e.altKey) {
      setView((v) => ({ ...v, x: v.x - e.deltaX, y: v.y - e.deltaY }));
      return;
    }
    const rect = box.current!.getBoundingClientRect();
    const px = e.clientX - rect.left, py = e.clientY - rect.top;
    setView((v) => {
      const k = Math.min(2.5, Math.max(0.2, v.k * (e.deltaY < 0 ? 1.1 : 0.9)));
      return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k };
    });
  };

  const toggle = (id: string) => setExpanded((e) => { const n = new Set(e); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  // Keyboard: ARIA tree pattern
  const onKey = (e: React.KeyboardEvent) => {
    const n = byId.get(focusId);
    if (!n) return;
    const siblings = n.parent ? (n.parent.children ?? []) : [n];
    const i = siblings.indexOf(n);
    let next: PNode | undefined;
    if (e.key === "ArrowRight") {
      if (n.data.children?.length && !expanded.has(n.data.id)) { toggle(n.data.id); e.preventDefault(); return; }
      next = n.children?.[0];
    } else if (e.key === "ArrowLeft") {
      if (expanded.has(n.data.id) && n.children?.length) { toggle(n.data.id); e.preventDefault(); return; }
      next = n.parent ?? undefined;
    } else if (e.key === "ArrowDown") next = siblings[i + 1];
    else if (e.key === "ArrowUp") next = siblings[i - 1];
    else if (e.key === "Enter" || e.key === " ") { setSelected(n.data.id); e.preventDefault(); return; }
    else return;
    e.preventDefault();
    if (next) { setFocusId(next.data.id); centerOn(next.data.id); }
  };

  const exportImg = async (fmt: "svg" | "png") => {
    const src = svg.current;
    if (!src) return;
    const clone = src.cloneNode(true) as SVGSVGElement;
    const w = layout.width + 80, h = layout.maxY - layout.minY + 80;
    clone.setAttribute("viewBox", `-40 ${layout.minY - 40} ${w} ${h}`);
    clone.setAttribute("width", String(w));
    clone.setAttribute("height", String(h));
    clone.querySelector("g[data-view]")?.removeAttribute("transform");
    const css = getComputedStyle(document.documentElement);
    const resolved = new XMLSerializer().serializeToString(clone).replace(/var\((--[\w-]+)\)/g, (_, v) => css.getPropertyValue(v).trim() || "#888");
    const bg = css.getPropertyValue("--bg-app").trim();
    const full = resolved.replace("<svg", `<svg style="background:${bg};font-family:Segoe UI,Arial,sans-serif"`);
    const blob = new Blob([full], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    if (fmt === "svg") {
      a.href = url; a.download = `${d.id}-tree.svg`; a.click();
      return;
    }
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = w * 2; c.height = h * 2;
      const ctx = c.getContext("2d")!;
      ctx.fillStyle = bg; ctx.fillRect(0, 0, c.width, c.height);
      ctx.scale(2, 2); ctx.drawImage(img, 0, 0);
      a.href = c.toDataURL("image/png"); a.download = `${d.id}-tree.png`; a.click();
      URL.revokeObjectURL(url);
    };
    img.src = url;
  };

  const sel = selected ? byId.get(selected) : null;
  const siblingsOfSel = sel?.parent?.children ?? [];
  const selIdx = sel ? siblingsOfSel.indexOf(sel) : -1;
  const highlight = new Set(matches);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ButtonGroup className="max-w-full overflow-x-auto p-0.5">
          <Button size="sm" aria-label="Zoom out" onClick={() => zoom(1 / 1.2)}><Minus /></Button>
          <Button size="sm" className="w-16 tabular" onClick={() => setView((v) => ({ ...v, k: 1 }))} aria-label="Reset zoom">{Math.round(view.k * 100)}%</Button>
          <Button size="sm" aria-label="Zoom in" onClick={() => zoom(1.2)}><Plus /></Button>
          <Button size="sm" icon={<Maximize />} onClick={fit}>Fit</Button>
          <Button size="sm" icon={<ChevronsUpDown />} onClick={() => setExpanded(new Set(all))}>Expand all</Button>
          <Button size="sm" icon={<ChevronsDownUp />} onClick={() => setExpanded(new Set(["root", "c-cve", "c-campaign", "c-actor", "c-intel", "c-ttp"]))}>Collapse to level 3</Button>
        </ButtonGroup>
        <Input inputSize="sm" className="w-56" prefixIcon={<Search />} placeholder="Search nodes" value={q} aria-label="Search the tree"
          onChange={(e) => { setQ(e.target.value); setMatchIdx(0); }} onKeyDown={(e) => { if (e.key === "Enter") setMatchIdx((i) => i + 1); }}
          suffix={q ? `${matches.length ? (matchIdx % matches.length) + 1 : 0}/${matches.length}` : undefined} />
        <div className="ml-auto flex items-center gap-2">
          <Tooltip content="List view (text equivalent)"><Link href="?tab=list" className="inline-flex h-7 items-center gap-1.5 rounded-sm px-2 text-[13px] font-semibold text-accent-text hover:bg-accent-soft"><List className="size-4" />List view</Link></Tooltip>
          <Button size="sm" variant={minimap ? "secondary" : "tertiary"} icon={<MapIcon />} onClick={() => setMinimap(!minimap)} aria-pressed={minimap}>Minimap</Button>
          <Menu width={200} items={[{ label: "Export PNG", icon: <Download />, onSelect: () => exportImg("png") }, { label: "Export SVG", icon: <Download />, onSelect: () => exportImg("svg") }]}
            trigger={(p) => <Button {...p} size="sm" icon={<Download />}>Export</Button>} />
        </div>
      </div>

      <div ref={box} className="dot-grid relative h-[640px] overflow-hidden rounded-md border border-line select-none"
        onWheel={onWheel}
        onMouseDown={(e) => { if ((e.target as Element).closest("[data-node]")) return; drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; }}
        onMouseMove={(e) => { if (drag.current) setView((v) => ({ ...v, x: drag.current!.vx + e.clientX - drag.current!.x, y: drag.current!.vy + e.clientY - drag.current!.y })); }}
        onMouseUp={() => { drag.current = null; }} onMouseLeave={() => { drag.current = null; }}
        style={{ cursor: drag.current ? "grabbing" : "grab" }}>
        <svg ref={svg} width="100%" height="100%" role="tree" aria-label="Research tree" tabIndex={0} onKeyDown={onKey}
          onMouseDown={(e) => { e.preventDefault(); svg.current?.focus({ preventScroll: true }); }}
          aria-activedescendant={`tn-${focusId}`} className="outline-none focus-visible:outline-2 focus-visible:outline-[var(--focus-ring)]">
          <g data-view transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {layout.links.map((l) => {
              const s = l.source, t = l.target;
              const x1 = COL_X[s.depth] + SIZE[s.data.kind].w, y1 = s.x, x2 = COL_X[t.depth], y2 = t.x;
              const mx = (x1 + x2) / 2;
              const onPath = pathIds?.has(s.data.id) && pathIds?.has(t.data.id);
              return <path key={t.data.id} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none"
                stroke={onPath ? "var(--accent)" : "var(--g-300)"} strokeWidth={onPath ? 2 : 1.5} opacity={pathIds && !onPath ? 0.45 : 1} />;
            })}
            {layout.nodes.map((n) => (
              <NodeView key={n.data.id} n={n} expanded={expanded.has(n.data.id)} dim={!!pathIds && !pathIds.has(n.data.id)}
                selected={selected === n.data.id} focused={focusId === n.data.id} match={highlight.has(n.data.id)}
                onSelect={() => { setSelected(n.data.id); setFocusId(n.data.id); }} onToggle={() => toggle(n.data.id)} />
            ))}
          </g>
        </svg>
        {minimap && <Minimap layout={layout} view={view} box={box} onJump={(x, y) => setView((v) => ({ ...v, x, y }))} />}
        <p className="pointer-events-none absolute bottom-2 left-3 text-caption text-fg-muted">Drag to pan · Ctrl + scroll to zoom · arrow keys to move · Enter opens details</p>
      </div>

      <Drawer open={!!sel} onClose={() => setSelected(null)} width={sel?.data.kind === "detection" ? 640 : 480}
        title={sel?.data.kind === "detection" ? `${sel.data.label} query` : sel?.data.label ?? ""}
        subtitle={sel ? <span className="flex items-center gap-2"><span className="size-2 rounded-full" style={{ background: CLASSIFICATION[sel.data.cls ?? ""]?.color ?? "var(--accent)" }} />{CLASSIFICATION[sel.data.cls ?? ""]?.label ?? "Subject"}{sel.data.sub ? ` · ${sel.data.sub}` : ""}</span> : null}
        onPrev={selIdx > 0 ? () => setSelected(siblingsOfSel[selIdx - 1].data.id) : undefined}
        onNext={selIdx >= 0 && selIdx < siblingsOfSel.length - 1 ? () => setSelected(siblingsOfSel[selIdx + 1].data.id) : undefined}>
        {sel && <NodeDetails n={sel.data} rec={rec} canEdit={canEdit} />}
      </Drawer>
    </div>
  );
}

function NodeView({ n, expanded, dim, selected, focused, match, onSelect, onToggle }:
  { n: PNode; expanded: boolean; dim: boolean; selected: boolean; focused: boolean; match: boolean; onSelect: () => void; onToggle: () => void }) {
  const { kind, label, sub, cls, children, techId } = n.data;
  const { w, h } = SIZE[kind];
  const x = COL_X[n.depth], y = n.x - h / 2;
  const color = CLASSIFICATION[cls ?? ""]?.color ?? "var(--accent)";
  const hidden = !expanded && children?.length ? children.length : 0;
  const fill = kind === "subject" ? "var(--btn-primary)" : kind === "behaviour" ? "var(--g-25)" : "var(--bg-surface)";
  const stroke = selected ? "var(--accent)" : kind === "opportunity" ? "var(--cls-opportunity)" : "var(--border-default)";
  const text = kind === "subject" ? "#fff" : "var(--text-primary)";
  const lines = kind === "behaviour" || kind === "opportunity" ? wrap(label, w - 24, kind === "behaviour" && techId ? 2 : 2) : [label];
  const status = kind === "detection" ? QUERY_STATUS[sub ?? ""]?.tone : null;
  const dot = status === "success" ? "var(--success)" : status === "info" ? "var(--info)" : status === "accent" ? "var(--accent)" : "var(--g-400)";
  return (
    <g id={`tn-${n.data.id}`} data-node role="treeitem" aria-level={n.depth + 1} aria-expanded={children?.length ? expanded : undefined}
      aria-selected={selected} aria-setsize={n.parent?.children?.length ?? 1} aria-label={`${CLASSIFICATION[cls ?? ""]?.label ?? "Subject"}: ${label}`}
      opacity={dim ? 0.45 : 1} style={{ cursor: "pointer", transition: "opacity 200ms" }} onClick={onSelect}>
      <rect x={x} y={y} width={w} height={h} rx={kind === "detection" ? 4 : 8} fill={fill} stroke={stroke} strokeWidth={selected || focused ? 2 : 1}
        className={kind === "behaviour" ? "[fill:var(--g-25)] dark:[fill:#232833]" : undefined} />
      {match && <rect x={x - 3} y={y - 3} width={w + 6} height={h + 6} rx={10} fill="none" stroke="var(--sev-medium)" strokeWidth={2} strokeDasharray="4 3" />}
      {kind === "subject" && (
        <>
          <text x={x + 14} y={y + 26} fill={text} fontSize={16} fontWeight={600}>{wrap(label, w - 28, 1, 8.6)[0]}</text>
          <text x={x + 14} y={y + 46} fill="#E4E2F6" fontSize={12} fontFamily="var(--font-mono)">{sub}</text>
        </>
      )}
      {kind === "class" && (
        <>
          <circle cx={x + 16} cy={y + h / 2} r={4} fill={color} />
          <text x={x + 28} y={y + h / 2 + 5} fill={text} fontSize={14} fontWeight={600}>{label}</text>
          <text x={x + w - 12} y={y + h / 2 + 5} fill="var(--text-secondary)" fontSize={13} textAnchor="end">{sub}</text>
        </>
      )}
      {kind === "entity" && (
        <>
          <circle cx={x + 14} cy={y + h / 2} r={4} fill={color} />
          <text x={x + 26} y={y + 19} fill={text} fontSize={13} fontWeight={600} fontFamily={cls === "cve" ? "var(--font-mono)" : undefined}>{wrap(label, w - 40, 1)[0]}</text>
          {sub && <text x={x + 26} y={y + 35} fill="var(--text-secondary)" fontSize={11}>{wrap(sub, w - 40, 1, 6.4)[0]}</text>}
        </>
      )}
      {kind === "behaviour" && (
        <>
          {techId && (
            <>
              <rect x={x + 10} y={y + 8} width={techId.length * 7.4 + 12} height={18} rx={4} fill="var(--neutral-chip-bg)" />
              <text x={x + 16} y={y + 21} fill="var(--accent-text)" fontSize={11} fontWeight={600} fontFamily="var(--font-mono)">{techId}</text>
              <text x={x + w - 10} y={y + 21} fill="var(--text-tertiary)" fontSize={11} textAnchor="end" fontFamily="var(--font-mono)">{sub}</text>
            </>
          )}
          {lines.map((l, i) => <text key={i} x={x + 12} y={y + (techId ? 42 : 24) + i * 16} fill={text} fontSize={12.5}>{l}</text>)}
        </>
      )}
      {kind === "opportunity" && (
        <>
          <text x={x + 12} y={y + 20} fill="var(--cls-opportunity)" fontSize={12} fontWeight={700} fontFamily="var(--font-mono)">{sub}</text>
          {lines.map((l, i) => <text key={i} x={x + 12} y={y + 38 + i * 16} fill={text} fontSize={12.5}>{l}</text>)}
        </>
      )}
      {kind === "detection" && (
        <>
          <circle cx={x + 14} cy={y + h / 2} r={3.5} fill={dot} />
          <text x={x + 26} y={y + h / 2 + 4.5} fill={text} fontSize={12} fontWeight={600}>{label}</text>
        </>
      )}
      {children?.length ? (
        <g onClick={(e) => { e.stopPropagation(); onToggle(); }} role="button" aria-label={expanded ? "Collapse" : `Expand ${children.length}`}>
          <circle cx={x + w} cy={n.x} r={hidden ? 12 : 8} fill="var(--bg-surface)" stroke="var(--border-default)" />
          <text x={x + w} y={n.x + 4} fontSize={hidden ? 10.5 : 12} fontWeight={600} textAnchor="middle" fill="var(--text-secondary)">{hidden ? `+${hidden}` : "−"}</text>
        </g>
      ) : null}
    </g>
  );
}

function Minimap({ layout, view, box, onJump }: { layout: { nodes: PNode[]; minY: number; maxY: number; width: number }; view: { x: number; y: number; k: number }; box: React.RefObject<HTMLDivElement | null>; onJump: (x: number, y: number) => void }) {
  const W = 160, H = 100;
  const h = layout.maxY - layout.minY + 40;
  const s = Math.min(W / (layout.width + 40), H / h);
  const el = box.current;
  const vw = el ? el.clientWidth / view.k : 0, vh = el ? el.clientHeight / view.k : 0;
  const vx = -view.x / view.k, vy = -view.y / view.k;
  return (
    <svg width={W} height={H} className="absolute right-3 bottom-3 rounded-sm border border-line bg-surface shadow-elev-2" aria-hidden
      onClick={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        const cx = (e.clientX - r.left) / s, cy = (e.clientY - r.top) / s + layout.minY - 20;
        if (el) onJump(el.clientWidth / 2 - cx * view.k, el.clientHeight / 2 - cy * view.k);
      }}>
      <g transform={`scale(${s}) translate(0 ${-layout.minY + 20})`}>
        {layout.nodes.map((n) => <rect key={n.data.id} x={COL_X[n.depth]} y={n.x - SIZE[n.data.kind].h / 2} width={SIZE[n.data.kind].w} height={SIZE[n.data.kind].h} rx={6}
          fill={n.depth === 0 ? "var(--btn-primary)" : "var(--g-300)"} />)}
        <rect x={vx} y={vy} width={vw} height={vh} fill="none" stroke="var(--accent)" strokeWidth={2 / s} />
      </g>
    </svg>
  );
}

function NodeDetails({ n, rec, canEdit }: { n: TNode; rec: ResearchRecord; canEdit: boolean }) {
  const sources = Object.fromEntries(rec.sources.map((s) => [s.id, s]));
  if (n.kind === "detection") {
    const q = n.data as unknown as Query;
    const siblings = rec.hunts.queries.filter((x) => x.opportunity_id === q.opportunity_id);
    return <QueryBlock title={q.title} refId={q.opportunity_id} queries={siblings} defaultPlatform={q.platform} canEdit={canEdit} />;
  }
  if (n.kind === "opportunity") {
    const o = n.data as unknown as ResearchRecord["detection_opportunities"][number];
    const qs = rec.hunts.queries.filter((x) => x.opportunity_id === o.id);
    return (
      <div className="space-y-4">
        <p className="text-[14px]">{o.logic}</p>
        <div className="flex flex-wrap gap-1.5">{o.techniques.map((t) => <AttackChip key={t} id={t} />)}</div>
        <p className="text-body-sm"><span className="text-fg-muted">Data sources: </span>{o.data_sources.map((x) => DATA_SOURCES[x] ?? x).join(", ")}</p>
        {o.fp_notes && <p className="text-body-sm"><span className="text-fg-muted">False positives: </span>{o.fp_notes}</p>}
        {qs.length > 0 && <QueryBlock title={o.title} refId={o.id} queries={qs} canEdit={canEdit} />}
      </div>
    );
  }
  if (n.kind === "behaviour") {
    const s = n.data as unknown as { behaviour: string; technique_id: string; source_ids: string[]; ref: string };
    const m = rec.mitre.filter((x) => x.technique_id === s.technique_id);
    return (
      <div className="space-y-4">
        <code className="block rounded-sm bg-code p-3 font-mono text-mono break-words">{s.behaviour}</code>
        <AttackChip id={s.technique_id} name={m[0]?.sub_technique || m[0]?.technique} tactic={m[0]?.tactic} />
        {m.map((x, i) => (
          <div key={i} className="rounded-md border border-line p-3">
            <p className="text-caption text-fg-muted">{x.tactic} · {x.confidence} confidence</p>
            <p className="mt-1 text-[14px]">{x.procedure}</p>
            {x.evidence_quote && <p className="mt-2 text-[14px]"><Quote>{x.evidence_quote}</Quote><SourceRefs ids={x.source_ids} sources={sources} /></p>}
          </div>
        ))}
        <p className="text-body-sm"><span className="text-fg-muted">Sources: </span>{s.source_ids.map((id) => sources[id]?.publisher ?? id).join(", ")}</p>
        <a href={`https://attack.mitre.org/techniques/${s.technique_id.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer" className="prose-link text-[14px]">View on attack.mitre.org</a>
      </div>
    );
  }
  if (n.kind === "entity" && n.data) {
    return (
      <div className="space-y-3 text-[14px]">
        {Object.entries(n.data).filter(([k, v]) => !["source_ids", "steps"].includes(k) && v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => (
          <div key={k}><span className="text-caption text-fg-muted">{k.replace(/_/g, " ")}</span><div>{Array.isArray(v) ? v.join(", ") : String(v)}</div></div>
        ))}
        {"steps" in n.data && Array.isArray(n.data.steps) && (
          <ol className="list-decimal space-y-1 pl-5">{(n.data.steps as { behaviour: string; technique_id: string }[]).map((s, i) => <li key={i}>{s.behaviour} <span className="font-mono text-mono-sm text-fg-muted">{s.technique_id}</span></li>)}</ol>
        )}
        {n.sources && <p><span className="text-fg-muted">Sources: </span><SourceRefs ids={n.sources} sources={sources} /></p>}
      </div>
    );
  }
  if (n.kind === "class") return <p className="text-[14px]">{n.children?.length ?? 0} item(s). Expand the node to explore them.</p>;
  return (
    <div className="space-y-2 text-[14px]">
      <p>{rec.title}</p>
      <div className="flex flex-wrap gap-1.5">{rec.classification.map((c) => <Chip key={c}>{c.replace("_", " ")}</Chip>)}</div>
      <Badge>{rec.mitre.length} technique mappings</Badge>
    </div>
  );
}
