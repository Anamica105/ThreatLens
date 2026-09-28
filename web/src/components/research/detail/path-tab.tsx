"use client";

import { ArrowRight, Download, ExternalLink, List, Map as MapIcon, Maximize, Minus, Plus, Search, X } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CLASSIFICATION, CLASSIFICATION_NAMES, CREDIBILITY, DATA_SOURCES, IOC_TYPE_LABEL, PATH_STAGES, PROVENANCE, QUERY_STATUS, QUERY_TYPE, RELIABILITY, SOURCE_ORIGIN,
} from "@/lib/constants";
import { utc } from "@/lib/format";
import type { ResearchRecord } from "@/lib/types";
import { useApp } from "../../providers";
import { AttackChip, Badge, Chip, ConfidenceBadge, SeverityBadge, SourceRating, TlpBadge } from "../../ui/badges";
import { Button, ButtonGroup } from "../../ui/button";
import { Input } from "../../ui/forms";
import { Drawer, Menu, Tooltip } from "../../ui/overlay";
import { IocValue } from "../ioc-value";
import { SourceChips, sourceIndex } from "../provenance";
import { QueryBlock } from "../query-block";
import { Quote, SourceRefs, type DetailProps } from "./common";
import {
  buildPathModel, COL_W, COLLAPSE_AT, layoutPath, lineage, orderColumns, W,
  type NodeData, type PathLayout, type PathModel, type Placed, type PNode,
} from "./path-model";

function wrap(text: string, width: number, lines: number, px = 7): string[] {
  const max = Math.max(4, Math.floor(width / px));
  const words = text.replace(/\s+/g, " ").trim().split(" ");
  const out: string[] = [];
  let cur = "";
  let i = 0;
  for (; i < words.length; i++) {
    const w = words[i];
    const next = cur ? `${cur} ${w}` : w;
    if (next.length <= max) { cur = next; continue; }
    if (cur) out.push(cur);
    if (out.length === lines) { cur = ""; break; }
    cur = w.length > max ? w.slice(0, max - 1) + "…" : w;
  }
  if (cur && out.length < lines) out.push(cur);
  const truncated = i < words.length || out.join(" ").length < text.replace(/\s+/g, " ").trim().length;
  if (truncated && out.length) {
    const last = out[out.length - 1];
    out[out.length - 1] = (last.length >= max ? last.slice(0, max - 1) : last).replace(/…$/, "") + "…";
  }
  return out;
}
const clip = (s: string, width: number, px = 7) => wrap(s, width, 1, px)[0] ?? "";

const STATUS_DOT: Record<string, string> = {
  success: "var(--success)", info: "var(--info)", accent: "var(--accent)", neutral: "var(--g-400)", muted: "var(--g-300)", warning: "var(--warning)",
};
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export function PathTab({ d, canEdit }: DetailProps) {
  const { platformName } = useApp();
  const rec = d.record;
  const model = useMemo(() => buildPathModel(d, (p) => platformName(p, true)), [d, platformName]);
  const ordered = useMemo(() => orderColumns(model), [model]);
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  const layout = useMemo(() => layoutPath(model, ordered, expanded), [model, ordered, expanded]);
  const all = useMemo(() => new Map(ordered.flat().map((n) => [n.id, n])), [ordered]);

  const [hover, setHover] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string>("subject");
  const [kbd, setKbd] = useState(false);
  const [q, setQ] = useState("");
  const [matchIdx, setMatchIdx] = useState(0);
  const [minimap, setMinimap] = useState(true);
  const [view, setView] = useState({ x: 24, y: 0, k: 0.7 });
  const [pending, setPending] = useState<string | null>(null);
  const box = useRef<HTMLDivElement | null>(null);
  const svg = useRef<SVGSVGElement | null>(null);
  const nodeRefs = useRef(new Map<string, SVGGElement | null>());
  const drag = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null);

  const active = hover ?? (kbd ? focusId : null) ?? selected;
  const lit = useMemo(() => (active && layout.byId.has(active) ? lineage(layout.edges, active) : null), [active, layout]);

  const degree = useMemo(() => {
    const up = new Map<string, number>(), down = new Map<string, number>();
    for (const e of model.edges) { up.set(e.to, (up.get(e.to) ?? 0) + 1); down.set(e.from, (down.get(e.from) ?? 0) + 1); }
    return { up, down };
  }, [model]);

  const skipIn = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const e of layout.edges) {
      const a = layout.byId.get(e.from), b = layout.byId.get(e.to);
      if (a && b && b.col - a.col > 1) m.set(b.id, [...(m.get(b.id) ?? []), a.id]);
    }
    return m;
  }, [layout]);

  const matches = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return [] as string[];
    return ordered.flat().filter((n) => n.search.toLowerCase().includes(t)).map((n) => n.id);
  }, [q, ordered]);
  const matchSet = useMemo(() => new Set(matches), [matches]);

  const centerOn = useCallback((id: string, lay: PathLayout = layout) => {
    const n = lay.byId.get(id);
    const el = box.current;
    if (!n || !el) return;
    setView((v) => ({ ...v, x: el.clientWidth / 2 - (n.x + n.w / 2) * v.k, y: el.clientHeight / 2 - (n.y + n.h / 2) * v.k }));
  }, [layout]);

  /** Make a node visible (expanding its column if it is folded into "+N more"), then centre on it. */
  const reveal = useCallback((id: string) => {
    const hiddenIn = layout.hiddenIn.get(id);
    if (hiddenIn) {
      const col = all.get(id)?.col;
      if (col !== undefined) setExpanded((e) => new Set([...e, col]));
    }
    setPending(id);
  }, [layout, all]);

  useEffect(() => {
    if (pending && layout.byId.has(pending)) { centerOn(pending); setPending(null); }
  }, [pending, layout, centerOn]);

  useEffect(() => {
    if (!matches.length) return;
    const id = matches[matchIdx % matches.length];
    setSelected(id);
    setFocusId(id);
    reveal(id);
  }, [matches, matchIdx]); // eslint-disable-line react-hooks/exhaustive-deps

  const fit = useCallback(() => {
    const el = box.current;
    if (!el) return;
    const top = layout.colTop - 12, h = layout.maxY - top + 24, w = layout.width + 48;
    const kW = (el.clientWidth - 16) / w, kH = (el.clientHeight - 16) / h;
    let k = Math.min(kW, kH, 1.1);
    if (k < 0.45) {
      k = Math.max(0.35, Math.min(kW, 1));
      setView({ k, x: Math.max(8, (el.clientWidth - layout.width * k) / 2), y: 16 - top * k });
      return;
    }
    setView({ k, x: (el.clientWidth - layout.width * k) / 2, y: (el.clientHeight - (layout.maxY + top) * k) / 2 });
  }, [layout]);

  useEffect(() => { fit(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const zoom = useCallback((f: number, px?: number, py?: number) => setView((v) => {
    const el = box.current;
    if (!el) return v;
    const cx = px ?? el.clientWidth / 2, cy = py ?? el.clientHeight / 2;
    const k = Math.min(2.5, Math.max(0.25, v.k * f));
    return { k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k };
  }), []);

  // Non-passive wheel: scroll pans the graph, Ctrl/⌘ + scroll zooms at the pointer.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      if (e.ctrlKey || e.metaKey) {
        const r = el.getBoundingClientRect();
        zoom(e.deltaY < 0 ? 1.1 : 0.9, e.clientX - r.left, e.clientY - r.top);
      } else setView((v) => ({ ...v, x: v.x - (e.shiftKey ? e.deltaY : e.deltaX), y: v.y - (e.shiftKey ? 0 : e.deltaY) }));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoom]);

  const open = useCallback((id: string) => {
    const n = all.get(id);
    if (!n || n.kind === "merge") return;
    if (n.kind === "more") { setExpanded((e) => new Set([...e, n.col])); return; }
    if (n.kind === "empty") return;
    setSelected(id);
    setFocusId(id);
    setOpenId(id);
    if (layout.hiddenIn.has(id)) reveal(id);
  }, [all, layout, reveal]);

  const toggleCol = (ci: number) => setExpanded((e) => { const n = new Set(e); if (n.has(ci)) n.delete(ci); else n.add(ci); return n; });

  // Keyboard navigation: ↑/↓ within a column, ←/→ to the nearest linked node in the next column, Enter opens details.
  const onKey = (e: React.KeyboardEvent) => {
    const cur = layout.byId.get(focusId) ?? layout.nodes[0];
    const col = layout.visibleCols[cur.col];
    const i = col.findIndex((n) => n.id === cur.id);
    let next: Placed | undefined;
    const nearest = (ci: number) => {
      const c = layout.visibleCols[ci];
      if (!c?.length) return undefined;
      const linked = c.filter((n) => layout.edges.some((ed) => (ed.from === cur.id && ed.to === n.id) || (ed.to === cur.id && ed.from === n.id)));
      const pool = linked.length ? linked : c;
      const cy = cur.y + cur.h / 2;
      return pool.reduce((a, b) => (Math.abs(b.y + b.h / 2 - cy) < Math.abs(a.y + a.h / 2 - cy) ? b : a));
    };
    if (e.key === "ArrowDown") next = col[i + 1];
    else if (e.key === "ArrowUp") next = col[i - 1];
    else if (e.key === "ArrowRight") next = nearest(cur.col + 1);
    else if (e.key === "ArrowLeft") next = nearest(cur.col - 1);
    else if (e.key === "Home") next = col[0];
    else if (e.key === "End") next = col[col.length - 1];
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(cur.id); return; }
    else if (e.key === "Escape") { setSelected(null); setKbd(false); return; }
    else return;
    e.preventDefault();
    setKbd(true);
    if (next) {
      setFocusId(next.id);
      const el = box.current;
      const sx = next.x * view.k + view.x, sy = next.y * view.k + view.y;
      if (el && (sx < 0 || sy < 0 || sx + next.w * view.k > el.clientWidth || sy + next.h * view.k > el.clientHeight)) centerOn(next.id);
    }
  };
  useEffect(() => { if (kbd) nodeRefs.current.get(focusId)?.focus({ preventScroll: true }); }, [focusId, kbd]);

  const exportImg = (fmt: "svg" | "png") => {
    const src = svg.current;
    if (!src) return;
    const clone = src.cloneNode(true) as SVGSVGElement;
    const top = layout.colTop - 24;
    const w = layout.width + 80, h = layout.maxY - top + 40;
    clone.setAttribute("viewBox", `-40 ${top} ${w} ${h}`);
    clone.setAttribute("width", String(w));
    clone.setAttribute("height", String(h));
    clone.querySelector("g[data-view]")?.removeAttribute("transform");
    clone.querySelectorAll("[opacity]").forEach((n) => n.removeAttribute("opacity"));
    const css = getComputedStyle(document.documentElement);
    const resolve = (s: string): string => s.replace(/var\((--[\w-]+)\)/g, (_, v) => resolve(css.getPropertyValue(v).trim() || "#888"));
    const bg = resolve("var(--bg-app)");
    const full = resolve(new XMLSerializer().serializeToString(clone)).replace("<svg", `<svg style="background:${bg};font-family:Segoe UI,Arial,sans-serif"`);
    const url = URL.createObjectURL(new Blob([full], { type: "image/svg+xml" }));
    const a = document.createElement("a");
    if (fmt === "svg") { a.href = url; a.download = `${d.id}-research-path.svg`; a.click(); return; }
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = w * 2; c.height = h * 2;
      const ctx = c.getContext("2d")!;
      ctx.fillStyle = bg; ctx.fillRect(0, 0, c.width, c.height);
      ctx.scale(2, 2); ctx.drawImage(img, 0, 0);
      a.href = c.toDataURL("image/png"); a.download = `${d.id}-research-path.png`; a.click();
      URL.revokeObjectURL(url);
    };
    img.src = url;
  };

  const pos = (id: string) => {
    if (id === "merge") return layout.merge ? { l: layout.merge.x, r: layout.merge.x, y: layout.merge.y } : null;
    const n = layout.byId.get(id);
    return n ? { l: n.x, r: n.x + n.w, y: n.y + n.h / 2 } : null;
  };

  const openNode = openId ? all.get(openId) ?? null : null;
  const openCol = openNode ? ordered[openNode.col] : [];
  const openIdx = openNode ? openCol.findIndex((n) => n.id === openNode.id) : -1;
  const stageLabel = (i: number) => {
    const n = model.counts[i];
    const s = PATH_STAGES[i];
    return plural(n, s.one, s.many);
  };

  return (
    <div className="min-w-0">
      {/* Stage summary strip */}
      <nav aria-label="Research path stages" className="mb-3 flex flex-wrap items-center gap-x-1 gap-y-1.5 rounded-md border border-line bg-surface px-3 py-2">
        {PATH_STAGES.map((s, i) => (
          <span key={s.id} className="inline-flex items-center gap-1">
            {i > 0 && <ArrowRight className="size-3.5 text-fg-faint" aria-hidden />}
            <button type="button" onClick={() => { const c = layout.visibleCols[i][0]; if (c) centerOn(c.id); }}
              className="inline-flex h-7 items-center gap-1.5 rounded-sm px-1.5 text-[13px] hover:bg-subtle" title={`Show the ${s.label} column`}>
              <span className="size-2 rounded-full" style={{ background: s.color }} aria-hidden />
              <span className="font-semibold tabular">{model.counts[i]}</span>
              <span className="text-fg-muted">{model.counts[i] === 1 ? s.one : s.many}</span>
            </button>
          </span>
        ))}
        <span className="ml-auto pl-2 text-caption text-fg-muted">
          {model.variants} platform variant{model.variants === 1 ? "" : "s"}{model.excludedSources ? ` · ${model.excludedSources} source${model.excludedSources === 1 ? "" : "s"} excluded` : ""}
        </span>
      </nav>

      {/* Toolbar */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ButtonGroup className="p-0.5">
          <Button size="sm" aria-label="Zoom out" onClick={() => zoom(1 / 1.2)}><Minus /></Button>
          <Button size="sm" className="w-16 tabular" onClick={() => setView((v) => ({ ...v, k: 1 }))} aria-label="Reset zoom to 100%">{Math.round(view.k * 100)}%</Button>
          <Button size="sm" aria-label="Zoom in" onClick={() => zoom(1.2)}><Plus /></Button>
          <Button size="sm" icon={<Maximize />} onClick={fit}>Fit</Button>
        </ButtonGroup>
        <Input inputSize="sm" className="w-full sm:w-60" prefixIcon={<Search />} placeholder="Search source, technique, DO-…" value={q} aria-label="Search the research path"
          onChange={(e) => { setQ(e.target.value); setMatchIdx(0); }} onKeyDown={(e) => { if (e.key === "Enter") setMatchIdx((i) => i + (e.shiftKey ? -1 + (matches.length || 1) : 1)); if (e.key === "Escape") setQ(""); }}
          suffix={q ? `${matches.length ? (matchIdx % matches.length) + 1 : 0}/${matches.length}` : undefined} />
        {(selected || kbd) && <Button size="sm" variant="tertiary" icon={<X />} onClick={() => { setSelected(null); setKbd(false); }}>Clear highlight</Button>}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Tooltip content="List view (text equivalent)"><Link href="?tab=list" className="inline-flex h-7 items-center gap-1.5 rounded-sm px-2 text-[13px] font-semibold text-accent-text hover:bg-accent-soft"><List className="size-4" />List view</Link></Tooltip>
          <Button size="sm" variant={minimap ? "secondary" : "tertiary"} icon={<MapIcon />} onClick={() => setMinimap(!minimap)} aria-pressed={minimap}>Minimap</Button>
          <Menu width={200} items={[{ label: "Export PNG", icon: <Download />, onSelect: () => exportImg("png") }, { label: "Export SVG", icon: <Download />, onSelect: () => exportImg("svg") }]}
            trigger={(p) => <Button {...p} size="sm" icon={<Download />}>Export</Button>} />
        </div>
      </div>

      {/* Graph */}
      <div ref={box} className="dot-grid relative h-[520px] touch-none overflow-hidden rounded-md border border-line select-none md:h-[680px]"
        onPointerDown={(e) => {
          if ((e.target as Element).closest("[data-node]")) return;
          drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
          (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
        }}
        onPointerMove={(e) => {
          const g = drag.current;
          if (!g) return;
          if (Math.abs(e.clientX - g.x) + Math.abs(e.clientY - g.y) > 3) g.moved = true;
          setView((v) => ({ ...v, x: g.vx + e.clientX - g.x, y: g.vy + e.clientY - g.y }));
        }}
        onPointerUp={() => { if (drag.current && !drag.current.moved) { setSelected(null); setKbd(false); } drag.current = null; }}
        onPointerCancel={() => { drag.current = null; }}
        style={{ cursor: drag.current ? "grabbing" : "grab" }}>
        <svg ref={svg} width="100%" height="100%" role="group" aria-roledescription="research path graph"
          aria-label={`Research path for ${d.id}: ${PATH_STAGES.map((_, i) => stageLabel(i)).join(", ")}. Use arrow keys to move between nodes and Enter to open details.`}
          onKeyDown={onKey} onMouseLeave={() => setHover(null)} className="outline-none">
          <g data-view transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {/* Column headers */}
            {PATH_STAGES.map((s, ci) => {
              const x = ci * COL_W, total = model.counts[ci];
              const foldable = ordered[ci].length > COLLAPSE_AT;
              return (
                <g key={s.id} aria-hidden>
                  <text x={x} y={layout.colTop + 14} fontSize={11} fontWeight={700} letterSpacing={0.6} fill="var(--text-secondary)">{`${ci + 1} · ${s.label.toUpperCase()}`}</text>
                  <text x={x + W} y={layout.colTop + 14} fontSize={12} fontWeight={700} textAnchor="end" fill="var(--text-primary)">{total}</text>
                  <rect x={x} y={layout.colTop + 22} width={W} height={3} rx={1.5} fill={s.color} opacity={0.85} />
                  {foldable && (
                    <text x={x + W} y={layout.colTop + 42} fontSize={11.5} fontWeight={600} textAnchor="end" fill="var(--accent-text)" style={{ cursor: "pointer" }} data-node
                      onClick={() => toggleCol(ci)}>{expanded.has(ci) ? "Show fewer" : `Show all ${ordered[ci].length}`}</text>
                  )}
                </g>
              );
            })}

            {/* Edges */}
            <g fill="none">
              {layout.edges.map((e) => {
                const a = pos(e.from), b = pos(e.to);
                if (!a || !b) return null;
                const x1 = a.r, x2 = b.l, mx = (x1 + x2) / 2;
                const on = !!lit && lit.has(e.from) && lit.has(e.to);
                const skip = x2 - x1 > COL_W;
                // Long links that jump a column are drawn only while their lineage is highlighted; a stub marks them otherwise.
                if (skip && !on) return null;
                return (
                  <path key={`${e.from}>${e.to}`} d={`M${x1},${a.y} C${skip ? x1 + 60 : mx},${a.y} ${skip ? x2 - 60 : mx},${b.y} ${x2},${b.y}`}
                    stroke={on ? "var(--accent)" : "var(--border-hover)"} strokeWidth={on ? 2 : 1.25}
                    strokeDasharray={e.inferred ? "5 4" : undefined} opacity={lit ? (on ? 1 : 0.12) : e.inferred || skip ? 0.7 : 1}
                    style={{ transition: "opacity 160ms, stroke 160ms" }} />
                );
              })}
            </g>
            {/* Stubs for links that skip columns (e.g. IoC retro-hunts built straight from sources) */}
            {Array.from(skipIn.entries()).map(([to, froms]) => {
              const b = layout.byId.get(to);
              if (!b) return null;
              const cy = b.y + b.h / 2;
              const on = !!lit && lit.has(to) && froms.some((f) => lit.has(f));
              const names = froms.map((f) => { const n = layout.byId.get(f); return n?.kind === "source" ? (n.data as { source: { id: string } }).source.id : n?.sub ?? "…"; });
              const txt = names.length > 3 ? `${names.slice(0, 2).join(" ")} +${names.length - 2}` : names.join(" ");
              return (
                <g key={`stub-${to}`} aria-hidden opacity={lit && !on && !lit.has(to) ? 0.15 : 1}>
                  <line x1={b.x - 40} y1={cy} x2={b.x} y2={cy} stroke={on ? "var(--accent)" : "var(--border-hover)"} strokeWidth={1.25} strokeDasharray="3 3" />
                  <circle cx={b.x - 40} cy={cy} r={2.5} fill={on ? "var(--accent)" : "var(--border-hover)"} />
                  <text x={b.x - 6} y={cy - 5} fontSize={10} textAnchor="end" fontFamily="var(--font-mono)" fill="var(--text-tertiary)">{txt}</text>
                </g>
              );
            })}
            {layout.merge && (
              <g aria-hidden opacity={lit && !lit.has("merge") ? 0.25 : 1}>
                <circle cx={layout.merge.x} cy={layout.merge.y} r={6} fill="var(--bg-surface)" stroke={lit?.has("merge") ? "var(--accent)" : "var(--border-hover)"} strokeWidth={1.5} />
                <circle cx={layout.merge.x} cy={layout.merge.y} r={2} fill={lit?.has("merge") ? "var(--accent)" : "var(--text-tertiary)"} />
              </g>
            )}

            {/* Nodes, one group per column */}
            {layout.visibleCols.map((col, ci) => (
              <g key={ci} role="list" aria-label={`${PATH_STAGES[ci].label}: ${stageLabel(ci)}`}>
                {col.map((n) => (
                  <g key={n.id} role="listitem">
                    <NodeView n={n} dim={!!lit && !lit.has(n.id)} lit={!!lit && lit.has(n.id) && active !== n.id} selected={selected === n.id}
                      focused={kbd && focusId === n.id} match={matchSet.has(n.id)} tabbable={focusId === n.id}
                      ups={degree.up.get(n.id) ?? 0} downs={degree.down.get(n.id) ?? 0}
                      refCb={(el) => { nodeRefs.current.set(n.id, el); }}
                      onHover={(h) => setHover(h ? n.id : null)} onFocus={() => setFocusId(n.id)} onOpen={() => open(n.id)} />
                  </g>
                ))}
              </g>
            ))}
          </g>
        </svg>
        {minimap && <Minimap layout={layout} view={view} box={box} lit={lit} onJump={(x, y) => setView((v) => ({ ...v, x, y }))} />}
      </div>
      <p className="mt-1.5 text-caption text-fg-muted">Hover a node to trace its lineage · click for details · drag or scroll to pan · Ctrl + scroll to zoom · Tab into the graph, then arrow keys and Enter</p>

      <Legend model={model} />

      <Drawer open={!!openNode} onClose={() => setOpenId(null)} width={openNode?.kind === "detection" ? 680 : 520}
        title={openNode ? drawerTitle(openNode) : ""}
        subtitle={openNode ? (
          <span className="flex min-w-0 items-center gap-2">
            <span className="size-2 shrink-0 rounded-full" style={{ background: openNode.kind === "classification" ? openNode.color : PATH_STAGES[openNode.col].color }} />
            <span className="truncate">{PATH_STAGES[openNode.col].label}{openNode.sub && openNode.kind !== "source" && openNode.kind !== "detection" ? ` · ${openNode.sub}` : ""}</span>
          </span>
        ) : null}
        onPrev={openIdx > 0 ? () => open(openCol[openIdx - 1].id) : undefined}
        onNext={openIdx >= 0 && openIdx < openCol.length - 1 ? () => open(openCol[openIdx + 1].id) : undefined}>
        {openNode && <PathDetails n={openNode} d={d} rec={rec} model={model} canEdit={canEdit} go={open} />}
      </Drawer>
    </div>
  );
}

function drawerTitle(n: PNode): string {
  if (n.kind === "detection" || n.kind === "opportunity") return n.sub && n.kind === "opportunity" ? `${n.sub} · ${n.label}` : n.label;
  return n.label;
}

function NodeView({ n, dim, lit, selected, focused, match, tabbable, ups, downs, refCb, onHover, onFocus, onOpen }: {
  n: Placed; dim: boolean; lit: boolean; selected: boolean; focused: boolean; match: boolean; tabbable: boolean; ups: number; downs: number;
  refCb: (el: SVGGElement | null) => void; onHover: (h: boolean) => void; onFocus: () => void; onOpen: () => void;
}) {
  const { x, y, w, h, kind } = n;
  const stroke = selected ? "var(--accent)" : lit ? "var(--accent)" : "var(--border-default)";
  const sw = selected || focused ? 2 : lit ? 1.5 : 1;
  const text = "var(--text-primary)";
  const label = ariaLabel(n, ups, downs);
  const common = {
    ref: refCb, "data-node": true, role: "button", tabIndex: tabbable ? 0 : -1, "aria-label": label, "aria-pressed": selected,
    opacity: dim ? 0.28 : 1, style: { cursor: kind === "empty" ? "default" : "pointer", transition: "opacity 160ms", outline: "none" } as React.CSSProperties,
    onMouseEnter: () => onHover(true), onMouseLeave: () => onHover(false), onFocus, onClick: onOpen,
  };
  const ring = (
    <>
      {focused && <rect x={x - 4} y={y - 4} width={w + 8} height={h + 8} rx={11} fill="none" stroke="var(--focus-ring)" strokeWidth={2} />}
      {match && <rect x={x - 5} y={y - 5} width={w + 10} height={h + 10} rx={12} fill="none" stroke="var(--sev-medium)" strokeWidth={2} strokeDasharray="4 3" />}
    </>
  );

  if (kind === "more" || kind === "empty") {
    return (
      <g {...common}>
        <rect x={x} y={y} width={w} height={h} rx={8} fill="var(--bg-subtle)" stroke="var(--border-hover)" strokeDasharray="4 4" />
        {ring}
        <text x={x + w / 2} y={y + h / 2 + 4.5} textAnchor="middle" fontSize={12.5} fontWeight={600} fill={kind === "more" ? "var(--accent-text)" : "var(--text-secondary)"}>
          {kind === "more" ? `${n.label} · show all` : clip(n.label, w - 20)}
        </text>
      </g>
    );
  }

  if (kind === "subject") {
    const lines = wrap(n.label, w - 30, 3, 7.9);
    return (
      <g {...common}>
        <rect x={x} y={y} width={w} height={h} rx={10} fill="var(--btn-primary)" stroke={selected ? "var(--accent-text)" : "transparent"} strokeWidth={2} />
        <rect x={x + 6} y={y + 10} width={3} height={h - 20} rx={1.5} fill={n.color} />
        {ring}
        {lines.map((l, i) => <text key={i} x={x + 18} y={y + 24 + i * 18} fill="#fff" fontSize={14} fontWeight={600}>{l}</text>)}
        <text x={x + 18} y={y + h - 14} fill="#E4E2F6" fontSize={11.5} fontFamily="var(--font-mono)">{n.sub}</text>
        <text x={x + w - 12} y={y + h - 14} fill="#E4E2F6" fontSize={11} fontWeight={600} textAnchor="end">{`TLP:${n.tag}`}</text>
      </g>
    );
  }

  if (kind === "classification") {
    return (
      <g {...common}>
        <rect x={x} y={y} width={w} height={h} rx={8} fill="var(--bg-surface)" stroke={stroke} strokeWidth={sw} />
        <rect x={x + 5} y={y + 9} width={3} height={h - 18} rx={1.5} fill={n.color} />
        {ring}
        <circle cx={x + 22} cy={y + h / 2} r={4.5} fill={n.color} />
        <text x={x + 34} y={y + h / 2 + 4.5} fill={text} fontSize={12.5} fontWeight={600}>{clip(n.label, w - 44, 6.4)}</text>
      </g>
    );
  }

  if (kind === "source") {
    const s = (n.data as Extract<NodeData, { kind: "source" }>).source;
    const origin = SOURCE_ORIGIN[s.origin ?? ""] ?? (s.origin ? s.origin.replace(/_/g, " ") : "Web search");
    const state = n.excluded ? "Excluded" : s.stale ? "Updated" : s.status === "read" || !s.status ? "Included" : s.status;
    return (
      <g {...common}>
        <rect x={x} y={y} width={w} height={h} rx={8} fill="var(--bg-surface)" stroke={stroke} strokeWidth={sw} strokeDasharray={n.excluded ? "5 4" : undefined} opacity={n.excluded ? 0.75 : 1} />
        <rect x={x + 5} y={y + 10} width={3} height={h - 20} rx={1.5} fill={n.color} />
        {ring}
        <text x={x + 16} y={y + 21} fill={text} fontSize={12.5} fontWeight={600} textDecoration={n.excluded ? "line-through" : undefined}>{clip(n.label, w - 22, 6.6)}</text>
        <rect x={x + w - 40} y={y + 45} width={30} height={18} rx={4} fill="var(--neutral-chip-bg)" />
        <text x={x + w - 25} y={y + 58} fontSize={11} fontWeight={700} textAnchor="middle" fontFamily="var(--font-mono)" fill="var(--neutral-chip-text)">{n.tag}</text>
        <text x={x + 16} y={y + 38} fill="var(--text-secondary)" fontSize={11.5}>{clip(s.title, w - 28, 6.3)}</text>
        <text x={x + 16} y={y + 58} fontSize={11} fill="var(--text-tertiary)">
          <tspan fontFamily="var(--font-mono)">{s.id}</tspan>
          <tspan> · {origin} · </tspan>
          <tspan fill={n.excluded ? "var(--danger)" : s.stale ? "var(--warning)" : "var(--success)"} fontWeight={600}>{state}</tspan>
        </text>
      </g>
    );
  }

  if (kind === "behaviour" || kind === "opportunity") {
    const isIoa = n.tag === "IoA";
    const lines = wrap(n.label, w - 28, 2, kind === "behaviour" ? 6.9 : 7.1);
    return (
      <g {...common}>
        <rect x={x} y={y} width={w} height={h} rx={8} fill="var(--bg-surface)" stroke={kind === "opportunity" && !selected && !lit ? "color-mix(in srgb, var(--cls-opportunity) 55%, var(--border-default))" : stroke} strokeWidth={sw} />
        <rect x={x + 5} y={y + 10} width={3} height={h - 20} rx={1.5} fill={n.color} />
        {ring}
        {kind === "behaviour" ? (
          <>
            <rect x={x + 14} y={y + 8} width={(n.tag?.length ?? 3) * 7.2 + 12} height={18} rx={4} fill={isIoa ? "var(--warning-soft)" : "var(--neutral-chip-bg)"} />
            <text x={x + 20} y={y + 21} fill={isIoa ? "var(--warning)" : "var(--accent-text)"} fontSize={11} fontWeight={700} fontFamily="var(--font-mono)">{n.tag}</text>
            <text x={x + w - 10} y={y + 21} fill="var(--text-tertiary)" fontSize={11} textAnchor="end" fontFamily="var(--font-mono)">{n.sub}</text>
          </>
        ) : (
          <>
            <text x={x + 16} y={y + 21} fill="var(--cls-opportunity)" fontSize={12} fontWeight={700} fontFamily="var(--font-mono)">{n.sub}</text>
            {n.tag && <text x={x + w - 10} y={y + 21} fill="var(--text-tertiary)" fontSize={11} fontWeight={600} textAnchor="end">{QUERY_TYPE[n.tag] ?? n.tag}</text>}
          </>
        )}
        {lines.map((l, i) => <text key={i} x={x + 16} y={y + 41 + i * 15} fill={text} fontSize={12.5}>{l}</text>)}
      </g>
    );
  }

  // detection
  const g = (n.data as Extract<NodeData, { kind: "detection" }>).group;
  const lines = wrap(n.label, w - 44, 2, 7.1);
  const shorts = (n.sub ?? "").split(" · ").filter(Boolean);
  const tone = QUERY_STATUS[g.status]?.tone ?? "neutral";
  let bx = x + 16;
  const badges: React.ReactNode[] = [];
  const maxX = x + w - 10;
  for (let i = 0; i < shorts.length; i++) {
    const t = shorts[i];
    const bw = t.length * 6.6 + 10;
    const remaining = shorts.length - i;
    if (bx + bw > maxX - (remaining > 1 ? 30 : 0)) {
      badges.push(<g key="more"><rect x={bx} y={y + 46} width={28} height={18} rx={4} fill="var(--neutral-chip-bg)" /><text x={bx + 14} y={y + 58.5} fontSize={10.5} fontWeight={600} textAnchor="middle" fill="var(--neutral-chip-text)">+{remaining}</text></g>);
      break;
    }
    badges.push(<g key={t + i}><rect x={bx} y={y + 46} width={bw} height={18} rx={4} fill="var(--neutral-chip-bg)" /><text x={bx + bw / 2} y={y + 58.5} fontSize={10.5} fontWeight={600} textAnchor="middle" fontFamily="var(--font-mono)" fill="var(--neutral-chip-text)">{t}</text></g>);
    bx += bw + 4;
  }
  return (
    <g {...common}>
      <rect x={x} y={y} width={w} height={h} rx={8} fill="var(--bg-surface)" stroke={stroke} strokeWidth={sw} />
      <rect x={x + 5} y={y + 10} width={3} height={h - 20} rx={1.5} fill={n.color} />
      {ring}
      {lines.map((l, i) => <text key={i} x={x + 16} y={y + 19 + i * 15} fill={text} fontSize={12.5} fontWeight={600}>{l}</text>)}
      <circle cx={x + w - 14} cy={y + 15} r={4.5} fill={STATUS_DOT[tone] ?? "var(--g-400)"}><title>{QUERY_STATUS[g.status]?.label ?? g.status}</title></circle>
      {badges}
      {!shorts.length && <text x={x + 16} y={y + 58} fontSize={11} fill="var(--text-tertiary)">Sigma only</text>}
    </g>
  );
}

function ariaLabel(n: PNode, ups: number, downs: number): string {
  const stage = PATH_STAGES[n.col]?.label ?? "";
  const links = `${ups ? `${ups} upstream link${ups === 1 ? "" : "s"}` : "no upstream links"}, ${downs ? `${downs} downstream link${downs === 1 ? "" : "s"}` : "no downstream links"}`;
  switch (n.data.kind) {
    case "subject": return `Subject ${n.sub}: ${n.label}. TLP ${n.tag}.`;
    case "source": return `Source ${n.data.source.id}, ${n.label}: ${n.data.source.title}. Reliability ${n.tag}${n.excluded ? ", excluded" : ""}. ${links}.`;
    case "behaviour": return `Attack behaviour ${n.sub}${n.tag && n.tag !== "IoA" ? `, ${n.tag}` : ", indicator of attack"}: ${n.label}. ${links}.`;
    case "opportunity": return `Detection opportunity ${n.sub}: ${n.label}. ${links}.`;
    case "detection": return `Detection: ${n.label}. Platforms ${n.sub?.split(" · ").join(", ") || "Sigma"}. Status ${QUERY_STATUS[n.data.group.status]?.label ?? n.data.group.status}. ${links}.`;
    case "more": return `${n.label} in ${stage}. Press Enter to show all.`;
    case "empty": return `${stage}: ${n.label}`;
    default: return `${stage}: ${n.label}. ${links}.`;
  }
}

function Minimap({ layout, view, box, lit, onJump }: { layout: PathLayout; view: { x: number; y: number; k: number }; box: React.RefObject<HTMLDivElement | null>; lit: Set<string> | null; onJump: (x: number, y: number) => void }) {
  const Wm = 168, Hm = 104;
  const top = layout.colTop, h = layout.maxY - top + 20;
  const s = Math.min(Wm / (layout.width + 20), Hm / h);
  const el = box.current;
  const vw = el ? el.clientWidth / view.k : 0, vh = el ? el.clientHeight / view.k : 0;
  const vx = -view.x / view.k, vy = -view.y / view.k;
  return (
    <svg width={Wm} height={Hm} className="absolute bottom-3 left-3 hidden rounded-sm border border-line bg-surface shadow-elev-2 sm:block" aria-hidden data-node
      onClick={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        const cx = (e.clientX - r.left) / s - 10, cy = (e.clientY - r.top) / s + top - 10;
        if (el) onJump(el.clientWidth / 2 - cx * view.k, el.clientHeight / 2 - cy * view.k);
      }}>
      <g transform={`scale(${s}) translate(10 ${-top + 10})`}>
        {layout.nodes.map((n) => <rect key={n.id} x={n.x} y={n.y} width={n.w} height={n.h} rx={8}
          fill={lit?.has(n.id) ? "var(--accent)" : n.kind === "subject" ? "var(--btn-primary)" : "var(--border-hover)"} />)}
        <rect x={vx} y={vy} width={vw} height={vh} fill="none" stroke="var(--accent)" strokeWidth={2 / s} />
      </g>
    </svg>
  );
}

function Legend({ model }: { model: PathModel }) {
  const classes = Array.from(new Set(model.cols[1].filter((n) => n.kind === "classification").map((n) => (n.data as { cls: string }).cls)));
  return (
    <section aria-label="Legend" className="mt-3 grid gap-x-8 gap-y-3 rounded-md border border-line bg-surface px-4 py-3 text-body-sm md:grid-cols-[auto_auto_1fr]">
      <div>
        <h3 className="mb-1.5 text-caption font-semibold text-fg-muted">Stages</h3>
        <ul className="space-y-1">
          {PATH_STAGES.map((s, i) => (
            <li key={s.id} className="flex items-center gap-2"><span className="h-3 w-1 rounded-full" style={{ background: s.color }} aria-hidden />{i + 1}. {s.label}</li>
          ))}
        </ul>
      </div>
      <div>
        <h3 className="mb-1.5 text-caption font-semibold text-fg-muted">Classification colours</h3>
        <ul className="space-y-1">
          {(classes.length ? classes : ["vulnerability_exploitation"]).map((c) => (
            <li key={c} className="flex items-center gap-2"><span className="size-2.5 rounded-full" style={{ background: CLASSIFICATION[c]?.color ?? "var(--accent)" }} aria-hidden />{CLASSIFICATION_NAMES[c] ?? c}</li>
          ))}
        </ul>
      </div>
      <div>
        <h3 className="mb-1.5 text-caption font-semibold text-fg-muted">Reading the path</h3>
        <ul className="space-y-1">
          <li className="flex items-center gap-2"><svg width="28" height="8" aria-hidden><line x1="0" y1="4" x2="28" y2="4" stroke="var(--border-hover)" strokeWidth="1.5" /></svg>Stated in the record: a source cites the behaviour, a behaviour yields the opportunity</li>
          <li className="flex items-center gap-2"><svg width="28" height="8" aria-hidden><line x1="0" y1="4" x2="28" y2="4" stroke="var(--border-hover)" strokeWidth="1.5" strokeDasharray="5 4" /></svg>Inferred link: matched by ATT&amp;CK technique, or indicators found in the query</li>
          <li className="flex items-center gap-2"><svg width="28" height="12" aria-hidden><circle cx="14" cy="6" r="5" fill="var(--bg-surface)" stroke="var(--border-hover)" strokeWidth="1.5" /></svg>All classifications scope one web search, so they meet at a single point</li>
          <li className="flex items-center gap-2"><span className="inline-block h-3 w-7 rounded-sm border border-dashed border-line-hover" aria-hidden />Dashed box: excluded source, or folded list (&ldquo;+N more&rdquo;)</li>
          <li className="flex items-center gap-2"><span className="inline-flex size-3 items-center justify-center rounded-full" style={{ background: "var(--success)" }} aria-hidden />Detection status dot: green reviewed or deployed, blue syntax-checked, grey generated</li>
        </ul>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Drawer details                                                      */
/* ------------------------------------------------------------------ */

function NodeLink({ id, go, children }: { id: string; go: (id: string) => void; children: React.ReactNode }) {
  return <button type="button" onClick={() => go(id)} className="text-left text-accent-text hover:underline">{children}</button>;
}

function Section({ title, count, children }: { title: string; count?: number; children: React.ReactNode }) {
  return (
    <section className="min-w-0">
      <h3 className="mb-2 flex items-baseline gap-2 text-h4 font-semibold">{title}{count !== undefined && <span className="text-caption font-normal text-fg-muted">{count}</span>}</h3>
      {children}
    </section>
  );
}

function PathDetails({ n, d, rec, model, canEdit, go }: { n: PNode; d: DetailProps["d"]; rec: ResearchRecord; model: PathModel; canEdit: boolean; go: (id: string) => void }) {
  const sources = useMemo(() => sourceIndex(rec), [rec]);
  const nodes = useMemo(() => new Map(model.cols.flat().map((x) => [x.id, x])), [model]);
  const ups = model.edges.filter((e) => e.to === n.id).map((e) => nodes.get(e.from)).filter((x): x is PNode => !!x);
  const downs = model.edges.filter((e) => e.from === n.id).map((e) => nodes.get(e.to)).filter((x): x is PNode => !!x);
  const linkList = (items: PNode[], empty: string) => items.length ? (
    <ul className="space-y-1.5 text-[14px]">
      {items.map((x) => (
        <li key={x.id} className="flex min-w-0 items-baseline gap-2">
          <span className="shrink-0 font-mono text-mono-sm text-fg-muted">{x.kind === "source" ? (x.data as { source: { id: string } }).source.id : x.sub && x.kind !== "detection" ? x.sub : ""}</span>
          <span className="min-w-0 break-words"><NodeLink id={x.id} go={go}>{x.label}</NodeLink>{model.edges.find((e) => (e.from === x.id && e.to === n.id) || (e.to === x.id && e.from === n.id))?.inferred && <span className="ml-1.5 text-caption text-fg-muted">(inferred)</span>}</span>
        </li>
      ))}
    </ul>
  ) : <p className="text-body-sm text-fg-muted">{empty}</p>;

  const data = n.data;
  if (data.kind === "subject") {
    return (
      <div className="space-y-5 text-[14px]">
        <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={d.severity} /><TlpBadge tlp={d.tlp} /><ConfidenceBadge level={d.confidence} /><span className="font-mono text-mono-sm text-fg-muted">{d.id}</span></div>
        <p className="reading break-words">{rec.executive_summary.split(/\n\n+/)[0]}</p>
        <Section title="Classified as">
          <div className="flex flex-wrap gap-1.5">{rec.classification.map((c) => <Chip key={c} dot={CLASSIFICATION[c]?.color}>{CLASSIFICATION_NAMES[c] ?? c}</Chip>)}</div>
        </Section>
        <Section title="Path at a glance">
          <ul className="space-y-1">{PATH_STAGES.slice(1).map((s, i) => <li key={s.id}>{model.counts[i + 1]} {model.counts[i + 1] === 1 ? s.one : s.many}</li>)}</ul>
        </Section>
      </div>
    );
  }
  if (data.kind === "classification") {
    const c = data.cls;
    const steps = rec.attack_paths;
    return (
      <div className="space-y-5 text-[14px]">
        <p className="text-fg-muted">The classification scopes the web search: it decides which vendor feeds, advisories and actor write-ups the source-discovery stage looks for.</p>
        {c === "vulnerability_exploitation" && (
          <Section title="Vulnerabilities" count={rec.vulnerabilities.length}>
            <ul className="space-y-1.5">{rec.vulnerabilities.map((v) => <li key={v.cve} className="break-words"><span className="font-mono">{v.cve}</span>{v.cvss ? ` · CVSS ${v.cvss}` : ""}<SourceRefs ids={v.source_ids} sources={sources} /></li>)}</ul>
          </Section>
        )}
        {c === "campaign" && (
          <Section title="Attack paths" count={steps.length}>
            <ul className="space-y-1.5">{steps.map((p) => <li key={p.id} className="break-words"><span className="font-mono text-mono-sm text-fg-muted">{p.id}</span> {p.name} <span className="text-fg-muted">· {p.steps.length} steps</span></li>)}</ul>
          </Section>
        )}
        {c === "actor_profile" && (
          <Section title="Threat actors" count={rec.threat_actors.length}>
            <ul className="space-y-1.5">{rec.threat_actors.map((a) => <li key={a.name}>{a.name}<SourceRefs ids={a.source_ids} sources={sources} /></li>)}</ul>
          </Section>
        )}
        {c === "malware" && (
          <Section title="Malware and tools" count={rec.malware_tools.length}>
            <ul className="space-y-1.5">{rec.malware_tools.map((m) => <li key={m.name}>{m.name} <span className="text-fg-muted">· {m.type}</span><SourceRefs ids={m.source_ids} sources={sources} /></li>)}</ul>
          </Section>
        )}
        {c === "ttp_trend" && (
          <Section title="Techniques" count={new Set(rec.mitre.map((m) => m.technique_id)).size}>
            <div className="flex flex-wrap gap-1.5">{Array.from(new Set(rec.mitre.map((m) => m.technique_id))).map((t) => <AttackChip key={t} id={t} />)}</div>
          </Section>
        )}
        <Section title="Feeds" count={downs.length ? model.counts[2] : 0}><p className="text-body-sm text-fg-muted">Every source in the next column.</p></Section>
      </div>
    );
  }
  if (data.kind === "source") {
    const s = data.source;
    const claims = rec.claims.filter((c) => c.source_ids.includes(s.id));
    const techniques = Array.from(new Map(rec.mitre.filter((m) => m.source_ids.includes(s.id)).map((m) => [m.technique_id, m])).values());
    const iocs = rec.iocs.filter((i) => i.source_ids.includes(s.id));
    const behaviours = downs.filter((x) => x.kind === "behaviour");
    const dets = model.cols[5].filter((x) => x.kind === "detection" && (x.data as Extract<NodeData, { kind: "detection" }>).group.sourceIds.includes(s.id));
    return (
      <div className="space-y-5 text-[14px]">
        <div className="space-y-2">
          <a href={s.url} target="_blank" rel="noopener noreferrer" className="inline-flex max-w-full items-start gap-1.5 font-semibold text-accent-text hover:underline">
            <span className="min-w-0 break-words">{s.title}</span><ExternalLink className="mt-1 size-3.5 shrink-0" />
          </a>
          <p className="font-mono text-mono-sm break-all text-fg-muted">{s.url}</p>
          <div className="flex flex-wrap items-center gap-2">
            <SourceRating reliability={s.reliability} credibility={s.credibility} />
            <span className="text-body-sm text-fg-muted">{RELIABILITY[s.reliability] ?? "Unknown reliability"} · {CREDIBILITY[s.credibility] ?? "unknown credibility"}</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={s.included === false ? "danger" : "success"}>{s.included === false ? "Excluded" : "Included"}</Badge>
            <Badge>{SOURCE_ORIGIN[s.origin ?? ""] ?? s.origin ?? "Web search"}</Badge>
            {s.type && <Badge tone="muted">{s.type}</Badge>}
            {s.stale && <Badge tone="warning">Changed since last read</Badge>}
          </div>
          <p className="text-caption text-fg-muted">Published {s.published ?? "—"} · last fetched {s.last_fetched ? utc(s.last_fetched, false) : "—"}</p>
          {s.summary && <p className="text-fg-strong break-words">{s.summary}</p>}
        </div>
        <Section title="Claims taken from it" count={claims.length}>
          {claims.length ? <ul className="list-disc space-y-1.5 pl-5">{claims.map((c, i) => <li key={i} className="break-words">{c.statement}{c.status && c.status !== "confirmed" && <Badge tone="warning" className="ml-2">{c.status}</Badge>}</li>)}</ul>
            : <p className="text-body-sm text-fg-muted">No claims cite this source.</p>}
        </Section>
        <Section title="Attack behaviours it supports" count={behaviours.length}>{linkList(behaviours, "No attack-path steps cite this source.")}</Section>
        <Section title="Techniques" count={techniques.length}>
          {techniques.length ? <div className="flex flex-wrap gap-1.5">{techniques.map((m) => <AttackChip key={m.technique_id} id={m.technique_id} name={m.sub_technique || m.technique} tactic={m.tactic} />)}</div>
            : <p className="text-body-sm text-fg-muted">No ATT&amp;CK mappings cite this source.</p>}
        </Section>
        <Section title="IoCs" count={iocs.length}>
          {iocs.length ? (
            <ul className="space-y-1.5">
              {iocs.slice(0, 12).map((i) => <li key={i.type + i.value} className="min-w-0"><IocValue type={i.type} value={i.value} verdict={i.verdict} compact /> <span className="text-caption text-fg-muted">{IOC_TYPE_LABEL[i.type] ?? i.type}</span></li>)}
              {iocs.length > 12 && <li><Link href="?tab=iocs" className="prose-link text-body-sm">All {iocs.length} IoCs from this source</Link></li>}
            </ul>
          ) : <p className="text-body-sm text-fg-muted">No indicators taken from this source.</p>}
        </Section>
        <Section title="Detections built from it" count={dets.length}>{linkList(dets, "No detections trace back to this source.")}</Section>
      </div>
    );
  }
  if (data.kind === "behaviour") {
    const tech = data.step?.technique_id;
    const mitre = tech ? rec.mitre.filter((m) => m.technique_id === tech) : [];
    const srcIds = Array.from(new Set([...(data.step?.source_ids ?? data.ioa?.source_ids ?? []), ...data.coveredIoas.flatMap((i) => i.source_ids)]));
    return (
      <div className="space-y-5 text-[14px]">
        <code className="block rounded-sm bg-code p-3 font-mono text-mono break-words whitespace-pre-wrap">{n.label}</code>
        {data.step && <p className="text-body-sm text-fg-muted">Step {data.step.ref} of <span className="text-fg">{data.step.path_id} · {data.step.path_name}</span></p>}
        {data.ioa && <p className="text-body-sm text-fg-muted">Indicator of attack {data.ioa.id} · {data.ioa.kind.replace(/_/g, " ")}</p>}
        {tech && <AttackChip id={tech} name={mitre[0]?.sub_technique || mitre[0]?.technique} tactic={mitre[0]?.tactic} />}
        <Section title="Sources" count={srcIds.length}><SourceChips ids={srcIds} sources={sources} label="" empty="No source cites this behaviour — treat as unsupported." /></Section>
        {mitre.length > 0 && (
          <Section title="Evidence" count={mitre.length}>
            <div className="space-y-2">
              {mitre.map((x, i) => (
                <div key={i} className="rounded-md border border-line p-3">
                  <p className="text-caption text-fg-muted">{x.tactic} · {x.confidence} confidence</p>
                  <p className="mt-1 break-words">{x.procedure}</p>
                  {x.evidence_quote && <p className="mt-2 break-words"><Quote>{x.evidence_quote}</Quote><SourceRefs ids={x.source_ids} sources={sources} /></p>}
                </div>
              ))}
            </div>
          </Section>
        )}
        {data.coveredIoas.length > 0 && (
          <Section title="Also recorded as IoA" count={data.coveredIoas.length}>
            <ul className="space-y-1.5">{data.coveredIoas.map((i) => <li key={i.id} className="break-words"><span className="font-mono text-mono-sm text-fg-muted">{i.id}</span> <code className="font-mono text-mono-sm">{i.description}</code><SourceRefs ids={i.source_ids} sources={sources} /></li>)}</ul>
          </Section>
        )}
        <Section title="Leads to" count={downs.length}>{linkList(downs, "No detection opportunity yet — a coverage gap.")}</Section>
        {tech && <a href={`https://attack.mitre.org/techniques/${tech.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer" className="prose-link inline-flex items-center gap-1">View {tech} on attack.mitre.org<ExternalLink className="size-3.5" /></a>}
      </div>
    );
  }
  if (data.kind === "opportunity") {
    const o = data.opp;
    const behaviourSources = ups.flatMap((u) => u.data.kind === "behaviour" ? (u.data.step?.source_ids ?? u.data.ioa?.source_ids ?? []) : []);
    const srcIds = o.source_ids?.length ? o.source_ids : Array.from(new Set(behaviourSources));
    return (
      <div className="space-y-5 text-[14px]">
        <p className="break-words">{o.logic}</p>
        <div className="flex flex-wrap gap-1.5">{o.techniques.map((t) => <AttackChip key={t} id={t} />)}</div>
        <dl className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-2 text-body-sm">
          <dt className="text-fg-muted">Type</dt><dd>{QUERY_TYPE[o.type] ?? o.type}</dd>
          <dt className="text-fg-muted">Data sources</dt><dd className="break-words">{o.data_sources.map((x) => DATA_SOURCES[x] ?? x).join(", ") || "—"}</dd>
          <dt className="text-fg-muted">False positives</dt><dd className="break-words">{o.fp_notes || "—"}</dd>
        </dl>
        <Section title="Sources" count={srcIds.length}><SourceChips ids={srcIds} sources={sources} label="" empty="No sources linked." /></Section>
        <Section title="From behaviour" count={ups.length}>{linkList(ups, "Not linked to an attack behaviour.")}</Section>
        <Section title="Detections" count={downs.length}>{linkList(downs, "No detections generated for this opportunity yet.")}</Section>
      </div>
    );
  }
  if (data.kind === "detection") {
    const g = data.group;
    return (
      <div className="space-y-4">
        <p className="text-body-sm text-fg-muted">{QUERY_TYPE[g.type] ?? g.type} detection · {g.queries.length} platform variant{g.queries.length === 1 ? "" : "s"} · {PROVENANCE[g.provenance]?.help}</p>
        <Section title="Traced from" count={ups.length}>{linkList(ups, "Not linked upstream.")}</Section>
        <QueryBlock title={g.title} refId={g.opportunityId ?? g.queries[0].group ?? null} queries={g.queries} canEdit={canEdit}
          provenance={g.provenance} sourceIds={g.sourceIds} sources={sources} />
      </div>
    );
  }
  return null;
}
