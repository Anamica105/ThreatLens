"use client";

import { hierarchy, tree as d3tree, type HierarchyPointNode } from "d3-hierarchy";
import { ChevronsDownUp, ChevronsUpDown, Download, List, Map as MapIcon, Maximize, Minus, PanelRight, Plus, Search } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { QUERY_STATUS } from "@/lib/constants";
import { useApp, useWsHref } from "../../providers";
import { Button, ButtonGroup } from "../../ui/button";
import { Input } from "../../ui/forms";
import { Menu, Tooltip } from "../../ui/overlay";
import { NodeDrawer, nodeColor } from "../tree/details";
import { accordion, branchIds, buildResearchTree, defaultExpanded, findPath, levelCounts, type TKind, type TNode } from "../tree/model";
import type { DetailProps } from "./common";

const WIDTH: Record<TKind, number> = { subject: 260, class: 230, behaviour: 270, opportunity: 250, detection: 140 };
const nodeH = (n: TNode) => n.kind === "subject" ? 64 : n.kind === "class" ? 44 : n.kind === "detection" ? 32 : n.kind === "behaviour" && n.context ? 80 : 64;
const COL_X = [0, 324, 618, 952, 1266];
/** Spec §12: above this many laid-out nodes only what is in the viewport (plus a margin) is rendered. */
const VIRTUAL_AT = 500;
const MARGIN = 300;

function wrap(text: string, width: number, lines: number, px = 7.2): string[] {
  const max = Math.max(4, Math.floor(width / px));
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
const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

type PNode = HierarchyPointNode<TNode>;

function virtualThreshold() {
  try { return Number(localStorage.getItem("tl.tree.virtualAt")) || VIRTUAL_AT; } catch { return VIRTUAL_AT; }
}

export function TreeTab({ d, canEdit }: DetailProps) {
  const { platformName } = useApp();
  const wsHref = useWsHref();
  const rec = d.record;
  const root = useMemo(() => buildResearchTree(d, (p) => platformName(p, true)), [d, platformName]);
  const [expanded, setExpanded] = useState<Set<string>>(() => defaultExpanded(root));
  const [selected, setSelected] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string>("root");
  const [q, setQ] = useState("");
  const [matchIdx, setMatchIdx] = useState(0);
  const [minimap, setMinimap] = useState(true);
  const [view, setView] = useState({ x: 40, y: 0, k: 0.85 });
  const [size, setSize] = useState({ w: 1000, h: 640 });
  const [virtualAt] = useState(virtualThreshold);
  const box = useRef<HTMLDivElement | null>(null);
  const svg = useRef<SVGSVGElement | null>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const all = useMemo(() => branchIds(root), [root]);
  const counts = useMemo(() => levelCounts(root), [root]);

  const layout = useMemo(() => {
    const h = hierarchy<TNode>(root, (n) => (expanded.has(n.id) ? n.children : undefined));
    const t = d3tree<TNode>().nodeSize([1, 1]).separation((a, b) => (nodeH(a.data) + nodeH(b.data)) / 2 + (a.parent === b.parent ? 12 : 24));
    const laid = t(h);
    const nodes = laid.descendants();
    const minY = Math.min(...nodes.map((n) => n.x - nodeH(n.data) / 2));
    const maxY = Math.max(...nodes.map((n) => n.x + nodeH(n.data) / 2));
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
    const walk = (n: TNode) => { if (`${n.label} ${n.sub ?? ""} ${n.tag ?? ""} ${n.context ?? ""} ${n.search}`.toLowerCase().includes(ql)) out.push(n.id); n.children.forEach(walk); };
    walk(root);
    return out;
  }, [q, root]);

  const reveal = useCallback((id: string) => {
    const parents = findPath(root, id).slice(0, -1).map((n) => n.id);
    setExpanded((e) => new Set([...e, ...parents]));
  }, [root]);

  // Centre after the layout for the new expansion state exists.
  const [centerReq, setCenterReq] = useState<{ id: string } | null>(null);
  const centerOn = useCallback((id: string) => setCenterReq({ id }), []);
  useEffect(() => {
    if (!centerReq) return;
    const n = byId.get(centerReq.id);
    const el = box.current;
    if (!n || !el) return;
    setView((v) => ({ ...v, x: el.clientWidth / 2 - (COL_X[n.depth] + WIDTH[n.data.kind] / 2) * v.k, y: el.clientHeight / 2 - n.x * v.k }));
    setCenterReq(null);
  }, [centerReq, byId]);

  useEffect(() => {
    if (!matches.length) return;
    const id = matches[matchIdx % matches.length];
    reveal(id);
    centerOn(id);
  }, [matches, matchIdx, reveal, centerOn]);

  const fit = useCallback((min = 0.2) => {
    const el = box.current;
    if (!el) return;
    const h = layout.maxY - layout.minY + 40;
    const k = Math.min(1.2, Math.max(min, Math.min((el.clientWidth - 40) / layout.width, (el.clientHeight - 40) / h)));
    const rootY = byId.get("root")?.x ?? 0;
    // When the whole tree cannot be read at this zoom, keep the subject in the middle instead.
    const cy = k > min ? (layout.minY + layout.maxY) / 2 : rootY;
    setView({ k, x: 20, y: el.clientHeight / 2 - cy * k });
  }, [layout, byId]);

  useEffect(() => { fit(0.7); /* initial: readable zoom */ }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const zoom = (f: number) => setView((v) => {
    const el = box.current!;
    const cx = el.clientWidth / 2, cy = el.clientHeight / 2;
    const k = Math.min(2.5, Math.max(0.1, v.k * f));
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
      const k = Math.min(2.5, Math.max(0.1, v.k * (e.deltaY < 0 ? 1.1 : 0.9)));
      return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k };
    });
  };

  const plainToggle = (id: string) => setExpanded((e) => { const n = new Set(e); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  /** Clicking a node: accordion (open this branch, close its open siblings). Leaves open their query instead. */
  const activate = (n: PNode) => {
    setFocusId(n.data.id);
    if (!n.data.children.length) { setSelected(n.data.id); return; }
    setExpanded((e) => accordion(e, n.data, n.parent?.data ?? null));
    centerOn(n.data.id);
  };
  const openDetails = (n: PNode) => { setSelected(n.data.id); setFocusId(n.data.id); };

  // Keyboard: ARIA tree pattern
  const onKey = (e: React.KeyboardEvent) => {
    const n = byId.get(focusId);
    if (!n) return;
    const siblings = n.parent ? (n.parent.children ?? []) : [n];
    const i = siblings.indexOf(n);
    let next: PNode | undefined;
    if (e.key === "ArrowRight") {
      if (n.data.children.length && !expanded.has(n.data.id)) { plainToggle(n.data.id); e.preventDefault(); return; }
      next = n.children?.[0];
    } else if (e.key === "ArrowLeft") {
      if (expanded.has(n.data.id) && n.children?.length) { plainToggle(n.data.id); e.preventDefault(); return; }
      next = n.parent ?? undefined;
    } else if (e.key === "ArrowDown") next = siblings[i + 1];
    else if (e.key === "ArrowUp") next = siblings[i - 1];
    else if (e.key === "Home") next = siblings[0];
    else if (e.key === "End") next = siblings[siblings.length - 1];
    else if (e.key === "Enter") { openDetails(n); e.preventDefault(); return; }
    else if (e.key === " ") { activate(n); e.preventDefault(); return; }
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
    clone.querySelectorAll("[data-details]").forEach((x) => x.remove());
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

  // Virtualised rendering: only nodes and links that intersect the viewport (in layout coordinates) plus a margin.
  const virtual = layout.nodes.length > virtualAt;
  const vp = { x0: (-view.x - MARGIN) / view.k, x1: (size.w - view.x + MARGIN) / view.k, y0: (-view.y - MARGIN) / view.k, y1: (size.h - view.y + MARGIN) / view.k };
  const inView = (x0: number, x1: number, y0: number, y1: number) => x1 >= vp.x0 && x0 <= vp.x1 && y1 >= vp.y0 && y0 <= vp.y1;
  const nodes = virtual
    ? layout.nodes.filter((n) => n.data.id === focusId || n.data.id === selected || inView(COL_X[n.depth], COL_X[n.depth] + WIDTH[n.data.kind], n.x - nodeH(n.data) / 2, n.x + nodeH(n.data) / 2))
    : layout.nodes;
  const links = virtual
    ? layout.links.filter((l) => inView(COL_X[l.source.depth], COL_X[l.target.depth], Math.min(l.source.x, l.target.x), Math.max(l.source.x, l.target.x)))
    : layout.links;

  const sel = selected ? byId.get(selected) : null;
  const highlight = new Set(matches);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ButtonGroup className="max-w-full overflow-x-auto p-0.5">
          <Button size="sm" aria-label="Zoom out" onClick={() => zoom(1 / 1.2)}><Minus /></Button>
          <Button size="sm" className="w-16 tabular" onClick={() => setView((v) => ({ ...v, k: 1 }))} aria-label="Reset zoom">{Math.round(view.k * 100)}%</Button>
          <Button size="sm" aria-label="Zoom in" onClick={() => zoom(1.2)}><Plus /></Button>
          <Button size="sm" icon={<Maximize />} onClick={() => fit()}>Fit</Button>
          <Button size="sm" icon={<ChevronsUpDown />} onClick={() => setExpanded(new Set(all))}>Expand all</Button>
          <Button size="sm" icon={<ChevronsDownUp />} onClick={() => setExpanded(defaultExpanded(root))}>Collapse to level 3</Button>
        </ButtonGroup>
        <Input inputSize="sm" className="w-56" prefixIcon={<Search />} placeholder="Search nodes" value={q} aria-label="Search the tree"
          onChange={(e) => { setQ(e.target.value); setMatchIdx(0); }} onKeyDown={(e) => { if (e.key === "Enter") setMatchIdx((i) => i + 1); }}
          suffix={q ? `${matches.length ? (matchIdx % matches.length) + 1 : 0}/${matches.length}` : undefined} />
        <div className="ml-auto flex items-center gap-2">
          <Tooltip content="List view (text equivalent)"><Link href={wsHref("?tab=list")} className="inline-flex h-7 items-center gap-1.5 rounded-sm px-2 text-[13px] font-semibold text-accent-text hover:bg-accent-soft"><List className="size-4" />List view</Link></Tooltip>
          <Button size="sm" variant={minimap ? "secondary" : "tertiary"} icon={<MapIcon />} onClick={() => setMinimap(!minimap)} aria-pressed={minimap}>Minimap</Button>
          <Menu width={200} items={[{ label: "Export PNG", icon: <Download />, onSelect: () => exportImg("png") }, { label: "Export SVG", icon: <Download />, onSelect: () => exportImg("svg") }]}
            trigger={(p) => <Button {...p} size="sm" icon={<Download />}>Export</Button>} />
        </div>
      </div>
      <p className="mb-2 text-caption text-fg-muted tabular">
        {counts.classes} classifications · {counts.behaviours} attack behaviours · {counts.opportunities} detection opportunities · {counts.detections} detections
      </p>

      <div ref={box} className="dot-grid relative h-[640px] overflow-hidden rounded-md border border-line select-none"
        onWheel={onWheel}
        onMouseDown={(e) => { if ((e.target as Element).closest("[data-node]")) return; drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false }; }}
        onMouseMove={(e) => { const g = drag.current; if (g) { g.moved = true; setView((v) => ({ ...v, x: g.vx + e.clientX - g.x, y: g.vy + e.clientY - g.y })); } }}
        onMouseUp={() => { drag.current = null; }} onMouseLeave={() => { drag.current = null; }}
        style={{ cursor: drag.current ? "grabbing" : "grab" }}>
        <svg ref={svg} width="100%" height="100%" role="tree" aria-label="Research tree" tabIndex={0} onKeyDown={onKey}
          data-total={layout.nodes.length} data-rendered={nodes.length} data-virtual={virtual || undefined}
          onMouseDown={(e) => { e.preventDefault(); svg.current?.focus({ preventScroll: true }); }}
          aria-activedescendant={`tn-${focusId}`} className="outline-none focus-visible:outline-2 focus-visible:outline-[var(--focus-ring)]">
          <g data-view transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {links.map((l) => {
              const s = l.source, t = l.target;
              const x1 = COL_X[s.depth] + WIDTH[s.data.kind], y1 = s.x, x2 = COL_X[t.depth], y2 = t.x;
              const mx = (x1 + x2) / 2;
              const onPath = pathIds?.has(s.data.id) && pathIds?.has(t.data.id);
              return <path key={t.data.id} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none"
                stroke={onPath ? "var(--accent)" : "var(--g-300)"} strokeWidth={onPath ? 2 : 1.5} opacity={pathIds && !onPath ? 0.45 : 1} />;
            })}
            {nodes.map((n) => (
              <NodeView key={n.data.id} n={n} expanded={expanded.has(n.data.id)} dim={!!pathIds && !pathIds.has(n.data.id)}
                selected={selected === n.data.id} focused={focusId === n.data.id} match={highlight.has(n.data.id)}
                onActivate={() => activate(n)} onDetails={() => openDetails(n)} />
            ))}
          </g>
        </svg>
        {minimap && <Minimap layout={layout} view={view} size={size} onJump={(x, y) => setView((v) => ({ ...v, x, y }))} />}
        <p className="pointer-events-none absolute bottom-2 left-3 hidden max-w-[calc(100%-200px)] rounded-sm bg-surface/90 px-1.5 text-caption text-fg-muted sm:block">
          Click a node to expand its branch · <PanelRight className="inline size-3.5 align-[-2px]" aria-hidden /> Details opens the drawer · Drag to pan · Ctrl + scroll to zoom · Arrows move, Space expands, Enter opens details
        </p>
      </div>

      <NodeDrawer node={sel?.data ?? null} siblings={sel?.parent?.data.children ?? []} rec={rec} canEdit={canEdit}
        onSelect={(n) => { setSelected(n.id); setFocusId(n.id); }} onClose={() => setSelected(null)} />
    </div>
  );
}

function NodeView({ n, expanded, dim, selected, focused, match, onActivate, onDetails }:
  { n: PNode; expanded: boolean; dim: boolean; selected: boolean; focused: boolean; match: boolean; onActivate: () => void; onDetails: () => void }) {
  const { kind, label, sub, children, tag, context } = n.data;
  const w = WIDTH[kind], h = nodeH(n.data);
  const x = COL_X[n.depth], y = n.x - h / 2;
  const color = nodeColor(n.data);
  const kids = children.length;
  const hidden = !expanded && kids ? kids : 0;
  const fill = kind === "subject" ? "var(--btn-primary)" : kind === "behaviour" ? "var(--g-25)" : "var(--bg-surface)";
  const stroke = selected ? "var(--accent)" : kind === "opportunity" ? "var(--cls-opportunity)" : kind === "class" ? color : "var(--border-default)";
  const text = kind === "subject" ? "#fff" : "var(--text-primary)";
  const lines = kind === "behaviour" || kind === "opportunity" ? wrap(label, w - 24, 2) : [label];
  const status = kind === "detection" ? QUERY_STATUS[sub ?? ""]?.tone : null;
  const dot = status === "success" ? "var(--success)" : status === "info" ? "var(--info)" : status === "accent" ? "var(--accent)" : "var(--g-400)";
  const hasDetails = kind !== "detection";
  const bx = x + w - 26, by = y + 6;
  return (
    <g id={`tn-${n.data.id}`} data-node role="treeitem" aria-level={n.depth + 1} aria-expanded={kids ? expanded : undefined}
      aria-selected={selected} aria-setsize={n.parent?.children?.length ?? 1} aria-posinset={(n.parent?.children?.indexOf(n) ?? 0) + 1}
      aria-label={`${label}${sub ? `, ${sub}` : ""}${kids ? `, ${kids} children` : kind === "detection" ? ", opens query" : ""}`}
      opacity={dim ? 0.45 : 1} style={{ cursor: "pointer", transition: "opacity 200ms" }} onClick={onActivate}>
      <title>{kids ? `${label} — click to ${expanded ? "collapse" : "expand"}` : kind === "detection" ? `${label} — click to open the query` : label}</title>
      <rect x={x} y={y} width={w} height={h} rx={kind === "detection" ? 4 : 8} fill={fill} stroke={stroke} strokeWidth={selected || focused ? 2 : 1}
        className={kind === "behaviour" ? "[fill:var(--g-25)] dark:[fill:#232833]" : undefined} />
      {focused && !selected && <rect x={x - 2} y={y - 2} width={w + 4} height={h + 4} rx={10} fill="none" stroke="var(--focus-ring)" strokeWidth={2} />}
      {match && <rect x={x - 3} y={y - 3} width={w + 6} height={h + 6} rx={10} fill="none" stroke="var(--sev-medium)" strokeWidth={2} strokeDasharray="4 3" />}
      {kind === "subject" && (
        <>
          <text x={x + 14} y={y + 26} fill={text} fontSize={16} fontWeight={600}>{wrap(label, w - 60, 1, 8.6)[0]}</text>
          <text x={x + 14} y={y + 46} fill="#E4E2F6" fontSize={12} fontFamily="var(--font-mono)">{sub}</text>
        </>
      )}
      {kind === "class" && (
        <>
          <rect x={x} y={y} width={5} height={h} rx={2} fill={color} />
          <text x={x + 16} y={y + h / 2 + 5} fill={text} fontSize={14} fontWeight={600}>{label}</text>
          <text x={x + w - 34} y={y + h / 2 + 5} fill="var(--text-secondary)" fontSize={12.5} textAnchor="end">{clip(sub ?? "", 20)}</text>
        </>
      )}
      {kind === "behaviour" && (
        <>
          {tag && (
            <>
              <rect x={x + 10} y={y + 8} width={Math.min(tag.length, 12) * 7.2 + 12} height={18} rx={4} fill="var(--neutral-chip-bg)" />
              <text x={x + 16} y={y + 21} fill="var(--accent-text)" fontSize={11} fontWeight={600} fontFamily="var(--font-mono)">{clip(tag, 12)}</text>
            </>
          )}
          {sub && <text x={x + w - 32} y={y + 21} fill="var(--text-tertiary)" fontSize={11} textAnchor="end" fontFamily="var(--font-mono)">{clip(sub, 16)}</text>}
          {lines.map((l, i) => <text key={i} x={x + 12} y={y + 42 + i * 16} fill={text} fontSize={12.5}>{l}</text>)}
          {context && <text x={x + 12} y={y + h - 8} fill="var(--text-secondary)" fontSize={11}>{wrap(context, w - 24, 1, 6.2)[0]}</text>}
        </>
      )}
      {kind === "opportunity" && (
        <>
          <text x={x + 12} y={y + 20} fill="var(--cls-opportunity)" fontSize={12} fontWeight={700} fontFamily="var(--font-mono)">{clip(sub ?? "", 14)}{tag ? <tspan fill="var(--text-tertiary)" fontWeight={500} fontFamily="var(--font-sans)"> · {tag}</tspan> : null}</text>
          {lines.map((l, i) => <text key={i} x={x + 12} y={y + 38 + i * 16} fill={text} fontSize={12.5}>{l}</text>)}
        </>
      )}
      {kind === "detection" && (
        <>
          <circle cx={x + 14} cy={y + h / 2} r={3.5} fill={dot} />
          <text x={x + 26} y={y + h / 2 + 4.5} fill={text} fontSize={12} fontWeight={600}>{clip(label, 14)}</text>
        </>
      )}
      {hasDetails && (
        <g data-details role="button" aria-label={`Details: ${label}`} onClick={(e) => { e.stopPropagation(); onDetails(); }}>
          <title>Open details</title>
          <rect x={bx} y={kind === "class" ? y + h / 2 - 10 : by} width={20} height={20} rx={4} fill={kind === "subject" ? "rgba(255,255,255,0.14)" : "var(--bg-surface)"}
            stroke={kind === "subject" ? "rgba(255,255,255,0.4)" : "var(--border-default)"} />
          <PanelRight x={bx + 3} y={(kind === "class" ? y + h / 2 - 10 : by) + 3} width={14} height={14} color={kind === "subject" ? "#fff" : "var(--text-secondary)"} strokeWidth={2} />
        </g>
      )}
      {kids ? (
        <g aria-hidden>
          <circle cx={x + w} cy={n.x} r={hidden ? 12 : 8} fill="var(--bg-surface)" stroke="var(--border-default)" />
          <text x={x + w} y={n.x + 4} fontSize={hidden ? 10.5 : 12} fontWeight={600} textAnchor="middle" fill="var(--text-secondary)">{hidden ? `+${hidden}` : "−"}</text>
        </g>
      ) : null}
    </g>
  );
}

function Minimap({ layout, view, size, onJump }: { layout: { nodes: PNode[]; minY: number; maxY: number; width: number }; view: { x: number; y: number; k: number }; size: { w: number; h: number }; onJump: (x: number, y: number) => void }) {
  const W = 160, H = 100;
  const h = layout.maxY - layout.minY + 40;
  const s = Math.min(W / (layout.width + 40), H / h);
  const vw = size.w / view.k, vh = size.h / view.k;
  const vx = -view.x / view.k, vy = -view.y / view.k;
  return (
    <svg width={W} height={H} className="absolute right-3 bottom-3 rounded-sm border border-line bg-surface shadow-elev-2" aria-hidden
      onClick={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        const cx = (e.clientX - r.left) / s, cy = (e.clientY - r.top) / s + layout.minY - 20;
        onJump(size.w / 2 - cx * view.k, size.h / 2 - cy * view.k);
      }}>
      <g transform={`scale(${s}) translate(0 ${-layout.minY + 20})`}>
        {layout.nodes.map((n) => <rect key={n.data.id} x={COL_X[n.depth]} y={n.x - nodeH(n.data) / 2} width={WIDTH[n.data.kind]} height={nodeH(n.data)} rx={6}
          fill={n.depth === 0 ? "var(--btn-primary)" : n.depth === 1 ? nodeColor(n.data) : "var(--g-300)"} />)}
        <rect x={vx} y={vy} width={vw} height={vh} fill="none" stroke="var(--accent)" strokeWidth={2 / s} />
      </g>
    </svg>
  );
}
