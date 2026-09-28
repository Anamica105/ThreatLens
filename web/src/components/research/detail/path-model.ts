import { CLASSIFICATION, CLASSIFICATION_NAMES, PATH_STAGES, SEVERITY, SOURCE_ORIGIN } from "@/lib/constants";
import type { ResearchDetail, ResearchRecord, Source } from "@/lib/types";
import { groupQueries, type DetectionGroup } from "../provenance";

/**
 * Research path model: a layered DAG with six fixed columns
 * (subject → classification → sources → attack behaviours → detection opportunities → detections).
 * Edges are many-to-many (a behaviour cites several sources), so this is not a tree.
 */

export type PKind = "subject" | "classification" | "source" | "behaviour" | "opportunity" | "detection" | "more" | "empty" | "merge";
export type Step = ResearchRecord["attack_paths"][number]["steps"][number] & { path_id: string; path_name: string };
export type Ioa = ResearchRecord["ioas"][number];
export type Opp = ResearchRecord["detection_opportunities"][number];

export type NodeData =
  | { kind: "subject" }
  | { kind: "classification"; cls: string }
  | { kind: "source"; source: Source }
  | { kind: "behaviour"; step?: Step; ioa?: Ioa; coveredIoas: Ioa[] }
  | { kind: "opportunity"; opp: Opp }
  | { kind: "detection"; group: DetectionGroup }
  | { kind: "more"; hidden: string[] }
  | { kind: "empty" }
  | { kind: "merge" };

export interface PNode {
  id: string; col: number; kind: PKind; label: string; sub?: string; color: string; search: string; data: NodeData;
  /** Short tag at the top right: technique, reliability, type. */
  tag?: string; excluded?: boolean;
}
/** `inferred` edges are links ThreatLens worked out (technique match, IoC in the query body) rather than ones stated in the record. */
export interface PEdge { from: string; to: string; inferred?: boolean }

export interface PathModel { cols: PNode[][]; edges: PEdge[]; counts: number[]; variants: number; excludedSources: number }

export const COLS = 6;
export const W = 220;
export const GAP = 76;
export const COL_W = W + GAP;
export const V_GAP = 10;
export const COLLAPSE_AT = 12;
export const SHOW_WHEN_COLLAPSED = 10;
export const MERGE_X = COL_W + W + GAP / 2;
export const HEIGHT: Record<PKind, number> = {
  subject: 116, classification: 46, source: 70, behaviour: 66, opportunity: 66, detection: 72, more: 38, empty: 56, merge: 0,
};

const words = (s: string) => new Set(s.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 4));

/** An IoA is already covered when most of its significant words appear in one attack-path step. */
function coveringStep(ioa: Ioa, steps: Step[]): Step | undefined {
  const iw = words(ioa.description);
  if (!iw.size) return undefined;
  let best: Step | undefined, score = 0;
  for (const s of steps) {
    const sw = words(s.behaviour);
    const hit = Array.from(iw).filter((w) => sw.has(w)).length / iw.size;
    if (hit > score) { score = hit; best = s; }
  }
  return score >= 0.5 ? best : undefined;
}

export function buildPathModel(d: ResearchDetail, platformShort: (p: string) => string): PathModel {
  const rec = d.record;
  const edges: PEdge[] = [];
  const add = (from: string, to: string, inferred?: boolean) => {
    if (!edges.some((e) => e.from === from && e.to === to)) edges.push({ from, to, inferred });
  };

  // 1 · Subject
  const sev = SEVERITY[d.severity] ?? SEVERITY.medium;
  const subject: PNode = {
    id: "subject", col: 0, kind: "subject", label: rec.title, sub: d.id, color: sev.solid, data: { kind: "subject" },
    tag: d.tlp, search: `${rec.title} ${d.id} ${d.tlp} ${sev.label}`,
  };

  // 2 · Classification
  const classes: PNode[] = (rec.classification ?? []).map((c) => ({
    id: `cls-${c}`, col: 1, kind: "classification", label: CLASSIFICATION_NAMES[c] ?? c.replace(/_/g, " "), color: CLASSIFICATION[c]?.color ?? "var(--accent)",
    data: { kind: "classification", cls: c }, search: `${c} ${CLASSIFICATION_NAMES[c] ?? ""}`,
  }));
  classes.forEach((c) => add("subject", c.id));

  // 3 · Sources — what the web search found
  const sources: PNode[] = rec.sources.map((s) => ({
    id: `src-${s.id}`, col: 2, kind: "source", label: s.publisher || s.title, sub: s.title, color: "var(--cls-intel)",
    data: { kind: "source", source: s }, tag: `${s.reliability ?? "F"}${s.credibility ?? 6}`, excluded: s.included === false,
    search: `${s.id} ${s.publisher} ${s.title} ${s.url} ${SOURCE_ORIGIN[s.origin ?? ""] ?? s.origin ?? ""}`,
  }));
  const srcIds = new Set(rec.sources.map((s) => s.id));
  if (classes.length && sources.length) {
    classes.forEach((c) => add(c.id, "merge"));
    sources.forEach((s) => add("merge", s.id));
  } else sources.forEach((s) => add("subject", s.id));

  // 4 · Attack behaviours: attack-path steps, plus IoAs no step already covers
  const steps: Step[] = rec.attack_paths.flatMap((p) => p.steps.map((s) => ({ ...s, path_id: p.id, path_name: p.name })));
  const stepNode = new Map<string, PNode>();
  const behaviours: PNode[] = steps.map((s) => {
    const n: PNode = {
      id: `beh-${s.ref}`, col: 3, kind: "behaviour", label: s.behaviour, sub: s.ref, color: "var(--cls-behaviour)", tag: s.technique_id,
      data: { kind: "behaviour", step: s, coveredIoas: [] }, search: `${s.ref} ${s.behaviour} ${s.technique_id} ${s.path_name}`,
    };
    stepNode.set(s.ref, n);
    return n;
  });
  const ioaAlias = new Map<string, string>();
  for (const ioa of rec.ioas ?? []) {
    const cover = coveringStep(ioa, steps);
    if (cover) {
      const n = stepNode.get(cover.ref)!;
      (n.data as Extract<NodeData, { kind: "behaviour" }>).coveredIoas.push(ioa);
      n.search += ` ${ioa.id} ${ioa.description}`;
      ioaAlias.set(ioa.id, n.id);
      continue;
    }
    const n: PNode = {
      id: `beh-${ioa.id}`, col: 3, kind: "behaviour", label: ioa.description, sub: ioa.id, color: "var(--cls-behaviour)", tag: "IoA",
      data: { kind: "behaviour", ioa, coveredIoas: [] }, search: `${ioa.id} ${ioa.description} ${ioa.kind}`,
    };
    ioaAlias.set(ioa.id, n.id);
    behaviours.push(n);
  }
  for (const b of behaviours) {
    const data = b.data as Extract<NodeData, { kind: "behaviour" }>;
    const ids = new Set([...(data.step?.source_ids ?? data.ioa?.source_ids ?? []), ...data.coveredIoas.flatMap((i) => i.source_ids)]);
    ids.forEach((sid) => srcIds.has(sid) && add(`src-${sid}`, b.id));
  }
  const parent = (t: string) => t.split(".")[0];
  const behByTech = (techs: string[]) => behaviours.filter((b) => b.tag && b.tag !== "IoA" && techs.some((t) => t === b.tag || parent(t) === b.tag || t === parent(b.tag!)));

  // 5 · Detection opportunities
  const opps: PNode[] = rec.detection_opportunities.map((o) => {
    const n: PNode = {
      id: `opp-${o.id}`, col: 4, kind: "opportunity", label: o.title, sub: o.id, color: "var(--cls-opportunity)", tag: o.type?.toUpperCase?.() === "IOA" ? "IoA" : o.type,
      data: { kind: "opportunity", opp: o }, search: `${o.id} ${o.title} ${o.logic} ${o.techniques.join(" ")}`,
    };
    const direct = stepNode.get(o.behaviour_ref)?.id ?? ioaAlias.get(o.behaviour_ref);
    if (direct) add(direct, n.id);
    else behByTech(o.techniques).forEach((b) => add(b.id, n.id, true));
    return n;
  });
  const oppIds = new Set(opps.map((o) => o.id));

  // 6 · Detections — one node per detection group, not per platform variant
  const groups = groupQueries(rec);
  const detections: PNode[] = groups.map((g) => {
    const n: PNode = {
      id: `det-${g.key}`, col: 5, kind: "detection", label: g.title, sub: g.platforms.filter((p) => p !== "sigma").map(platformShort).join(" · "),
      color: "var(--cls-detection)", tag: g.type, data: { kind: "detection", group: g },
      search: `${g.key} ${g.title} ${g.queries.map((q) => `${q.id} ${q.platform}`).join(" ")} ${g.queries[0]?.techniques.join(" ") ?? ""}`,
    };
    const explicit = g.queries.some((q) => q.source_ids);
    if (g.opportunityId && oppIds.has(`opp-${g.opportunityId}`)) add(`opp-${g.opportunityId}`, n.id);
    else {
      const bySource = () => g.sourceIds.filter((s) => srcIds.has(s)).forEach((s) => add(`src-${s}`, n.id, !explicit));
      const techs = Array.from(new Set(g.queries.flatMap((q) => q.techniques)));
      const byTech = behByTech(techs);
      if (g.provenance === "vendor" && g.sourceIds.length) bySource();
      else if (byTech.length) byTech.forEach((b) => add(b.id, n.id, true));
      else bySource();
    }
    return n;
  });

  const empty = (col: number, label: string): PNode => ({ id: `empty-${col}`, col, kind: "empty", label, color: PATH_STAGES[col].color, data: { kind: "empty" }, search: "" });
  const cols: PNode[][] = [
    [subject],
    classes.length ? classes : [empty(1, "Not classified yet")],
    sources.length ? sources : [empty(2, "No sources found")],
    behaviours.length ? behaviours : [empty(3, "No behaviours extracted")],
    opps.length ? opps : [empty(4, "No opportunities yet")],
    detections.length ? detections : [empty(5, "No detections yet")],
  ];
  return {
    cols, edges,
    counts: [1, classes.length, sources.length, behaviours.length, opps.length, detections.length],
    variants: rec.hunts?.queries?.length ?? 0,
    excludedSources: rec.sources.filter((s) => s.included === false).length,
  };
}

/* ------------------------------------------------------------------ */
/* Layout: barycentre ordering + isotonic vertical placement            */
/* ------------------------------------------------------------------ */

export interface Placed extends PNode { x: number; y: number; w: number; h: number }
export interface PathLayout {
  nodes: Placed[]; byId: Map<string, Placed>; edges: PEdge[]; minY: number; maxY: number; width: number;
  colTop: number; merge: { x: number; y: number } | null; visibleCols: Placed[][]; hiddenIn: Map<string, string>;
}

/** Order nodes inside each column to minimise crossings (a few down/up barycentre sweeps). */
export function orderColumns(model: PathModel): PNode[][] {
  const cols = model.cols.map((c) => [...c]);
  const pos = new Map<string, number>();
  const colOf = new Map<string, number>();
  const index = () => cols.forEach((c, ci) => c.forEach((n, i) => { pos.set(n.id, c.length > 1 ? i / (c.length - 1) : 0.5); colOf.set(n.id, ci); }));
  index();
  const up = new Map<string, string[]>(), down = new Map<string, string[]>();
  for (const e of model.edges) {
    if (e.from === "merge" || e.to === "merge") continue;
    up.set(e.to, [...(up.get(e.to) ?? []), e.from]);
    down.set(e.from, [...(down.get(e.from) ?? []), e.to]);
  }
  const sweep = (ci: number, nbrs: Map<string, string[]>) => {
    const c = cols[ci];
    const bary = c.map((n, i) => {
      const ns = (nbrs.get(n.id) ?? []).filter((x) => pos.has(x));
      return { n, i, b: ns.length ? ns.reduce((a, x) => a + pos.get(x)!, 0) / ns.length : pos.get(n.id)! };
    });
    bary.sort((a, b) => a.b - b.b || a.i - b.i);
    cols[ci] = bary.map((x) => x.n);
    index();
  };
  for (let it = 0; it < 4; it++) {
    for (let ci = 3; ci < COLS; ci++) sweep(ci, up);
    for (let ci = COLS - 2; ci >= 2; ci--) sweep(ci, down);
  }
  for (let ci = 3; ci < COLS; ci++) sweep(ci, up);
  return cols;
}

/** Weighted isotonic regression (pool adjacent violators). */
function pav(t: number[], w: number[]): number[] {
  const blocks: { v: number; w: number; n: number }[] = [];
  t.forEach((v, i) => {
    blocks.push({ v, w: w[i], n: 1 });
    while (blocks.length > 1 && blocks[blocks.length - 2].v > blocks[blocks.length - 1].v) {
      const b = blocks.pop()!, a = blocks.pop()!;
      blocks.push({ v: (a.v * a.w + b.v * b.w) / (a.w + b.w), w: a.w + b.w, n: a.n + b.n });
    }
  });
  return blocks.flatMap((b) => Array(b.n).fill(b.v));
}

/** Place a column's centres as close as possible to `desired` without overlapping, keeping order. */
function place(nodes: PNode[], desired: (number | null)[]): number[] {
  const hs = nodes.map((n) => HEIGHT[n.kind]);
  const off: number[] = [];
  hs.forEach((h, i) => off.push(i === 0 ? 0 : off[i - 1] + hs[i - 1] / 2 + V_GAP + h / 2));
  const known = desired.map((d, i) => (d === null ? null : d - off[i]));
  const firstKnown = known.find((k) => k !== null) ?? -off[off.length - 1] / 2;
  let last = firstKnown as number;
  const t = known.map((k) => (k === null ? last : (last = k)));
  const z = pav(t, desired.map((d) => (d === null ? 0.001 : 1)));
  return z.map((v, i) => v + off[i]);
}

export function layoutPath(model: PathModel, ordered: PNode[][], expanded: Set<number>): PathLayout {
  const hiddenIn = new Map<string, string>();
  const outDeg = new Map<string, number>(), inDeg = new Map<string, number>();
  for (const e of model.edges) { outDeg.set(e.from, (outDeg.get(e.from) ?? 0) + 1); inDeg.set(e.to, (inDeg.get(e.to) ?? 0) + 1); }
  const visibleCols: PNode[][] = ordered.map((c, ci) => {
    if (c.length <= COLLAPSE_AT || expanded.has(ci)) return c;
    // Keep the nodes that carry the path forward (have downstream links, most connections); fold the rest.
    const score = (n: PNode) => (outDeg.get(n.id) ? 1000 : 0) + (outDeg.get(n.id) ?? 0) * 10 + (inDeg.get(n.id) ?? 0);
    const keep = new Set([...c].sort((a, b) => score(b) - score(a)).slice(0, SHOW_WHEN_COLLAPSED).map((n) => n.id));
    const shown = c.filter((n) => keep.has(n.id)), rest = c.filter((n) => !keep.has(n.id));
    const more: PNode = {
      id: `more-${ci}`, col: ci, kind: "more", label: `+${rest.length} more`, color: PATH_STAGES[ci].color,
      data: { kind: "more", hidden: rest.map((n) => n.id) }, search: "",
    };
    rest.forEach((n) => hiddenIn.set(n.id, more.id));
    return [...shown, more];
  });
  const vis = (id: string) => hiddenIn.get(id) ?? id;
  const edges: PEdge[] = [];
  for (const e of model.edges) {
    const from = vis(e.from), to = vis(e.to);
    const ex = edges.find((x) => x.from === from && x.to === to);
    if (ex) { if (!e.inferred) ex.inferred = false; } else edges.push({ from, to, inferred: e.inferred });
  }
  const up = new Map<string, string[]>(), down = new Map<string, string[]>();
  for (const e of edges) { up.set(e.to, [...(up.get(e.to) ?? []), e.from]); down.set(e.from, [...(down.get(e.from) ?? []), e.to]); }

  const cy = new Map<string, number>();
  const mean = (ids: string[] | undefined) => {
    const ys = (ids ?? []).map((i) => cy.get(i)).filter((v): v is number => v !== undefined);
    return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : null;
  };
  const setCol = (ci: number, desired: (number | null)[]) => place(visibleCols[ci], desired).forEach((y, i) => cy.set(visibleCols[ci][i].id, y));
  const shift = (ci: number, centre: number) => {
    const c = visibleCols[ci];
    const top = cy.get(c[0].id)! - HEIGHT[c[0].kind] / 2, bot = cy.get(c[c.length - 1].id)! + HEIGHT[c[c.length - 1].kind] / 2;
    const dy = centre - (top + bot) / 2;
    c.forEach((n) => cy.set(n.id, cy.get(n.id)! + dy));
  };
  const stackCentered = (ci: number, centre = 0) => { setCol(ci, visibleCols[ci].map(() => null)); shift(ci, centre); };

  // Sources first (centred), then flow right, then pull sources toward what they feed, then centre the left side on the sources.
  stackCentered(2, 0);
  for (let ci = 3; ci < COLS; ci++) setCol(ci, visibleCols[ci].map((n) => mean(up.get(n.id)?.filter((u) => u !== "merge"))));
  setCol(2, visibleCols[2].map((n) => mean(down.get(n.id))));
  for (let ci = 3; ci < COLS; ci++) setCol(ci, visibleCols[ci].map((n) => mean(up.get(n.id)?.filter((u) => u !== "merge"))));
  const srcMid = (() => {
    const c = visibleCols[2];
    return (cy.get(c[0].id)! - HEIGHT[c[0].kind] / 2 + cy.get(c[c.length - 1].id)! + HEIGHT[c[c.length - 1].kind] / 2) / 2;
  })();
  stackCentered(1, srcMid);
  cy.set("subject", srcMid);

  const nodes: Placed[] = visibleCols.flatMap((c, ci) => c.map((n) => {
    const h = HEIGHT[n.kind];
    return { ...n, x: ci * COL_W, y: cy.get(n.id)! - h / 2, w: W, h };
  }));
  const hasMerge = model.edges.some((e) => e.to === "merge");
  const minY = Math.min(...nodes.map((n) => n.y));
  const maxY = Math.max(...nodes.map((n) => n.y + n.h));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  return {
    nodes, byId, edges, minY, maxY, width: (COLS - 1) * COL_W + W, colTop: minY - 56,
    merge: hasMerge ? { x: MERGE_X, y: srcMid } : null,
    visibleCols: visibleCols.map((c) => c.map((n) => byId.get(n.id)!)), hiddenIn,
  };
}

/** Full upstream + downstream lineage of a node (through the merge point). */
export function lineage(edges: PEdge[], id: string): Set<string> {
  const up = new Map<string, string[]>(), down = new Map<string, string[]>();
  for (const e of edges) { up.set(e.to, [...(up.get(e.to) ?? []), e.from]); down.set(e.from, [...(down.get(e.from) ?? []), e.to]); }
  const walk = (m: Map<string, string[]>) => {
    const seen = new Set<string>([id]);
    const stack = [id];
    while (stack.length) for (const n of m.get(stack.pop()!) ?? []) if (!seen.has(n)) { seen.add(n); stack.push(n); }
    return seen;
  };
  return new Set([...walk(up), ...walk(down)]);
}
