import { IOC_TYPE_LABEL } from "@/lib/constants";
import type { IocRow, Query, ResearchDetail, ResearchRecord } from "@/lib/types";
import { buildPathModel, type Ioa, type NodeData, type Opp, type Step } from "../detail/path-model";
import { groupQueries, type DetectionGroup } from "../provenance";

/**
 * Research hierarchy shared by the Tree view and the List view (spec §7.3):
 * Subject → Classification → Attack behaviours → Detection opportunities → Detections (one leaf per platform query).
 * The same behaviour can appear under several classifications (a step is both a TTP and part of the campaign);
 * node ids are path-based so each occurrence is unique.
 */

export type TKind = "subject" | "class" | "behaviour" | "opportunity" | "detection";
export type ClassKey = "cve" | "campaign" | "actor" | "intel" | "ttp";
type Malware = ResearchRecord["malware_tools"][number];

export type TRef =
  | { t: "subject" }
  | { t: "class"; cls: ClassKey }
  | { t: "step"; step: Step; coveredIoas: Ioa[] }
  | { t: "ioa"; ioa: Ioa }
  | { t: "technique"; techId: string }
  | { t: "malware"; items: Malware[] }
  | { t: "iocs"; iocType: string; iocs: IocRow[] }
  | { t: "exposure"; cves: string[] }
  | { t: "unmapped" }
  | { t: "opp"; opp: Opp }
  | { t: "group"; group: DetectionGroup }
  | { t: "query"; query: Query };

export interface TNode {
  id: string; kind: TKind; label: string;
  /** Short text at the top right of a node (step ref, CVSS, platform status). */
  sub?: string;
  /** Technique id or entity type shown as a chip. */
  tag?: string;
  /** Who/what the behaviour is attributed to (actors, malware), when it sits under that classification. */
  context?: string;
  cls: string; ref: TRef; children: TNode[]; search: string;
  /** ATT&CK tactic ids of the behaviour (inherited by its opportunities and detections). */
  tactics: string[];
  depth: number;
}

export const CLASS_META: Record<ClassKey, { label: string; color: string }> = {
  cve: { label: "CVE", color: "var(--cls-cve)" },
  campaign: { label: "Campaign", color: "var(--cls-campaign)" },
  actor: { label: "Threat actors", color: "var(--cls-actor)" },
  intel: { label: "Threat intel", color: "var(--cls-intel)" },
  ttp: { label: "TTPs", color: "var(--cls-ttp)" },
};

/** Techniques that describe exploiting a vulnerability (their behaviours sit under the CVE class). */
const EXPLOIT_TECHS = ["T1190", "T1203", "T1210", "T1211", "T1212", "T1068", "T1133"];
const parentTech = (t: string) => t.split(".")[0];
const sameTech = (a: string, b: string) => a === b || parentTech(a) === b || a === parentTech(b);
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Malware/tool name variants worth matching in behaviour text: full name, parenthesised alias, name without extension. */
function nameVariants(name: string): string[] {
  const out = new Set<string>();
  const lower = name.toLowerCase();
  out.add(lower.replace(/\s*\(.*\)\s*/, "").trim());
  const paren = lower.match(/\(([^)]+)\)/)?.[1];
  if (paren) out.add(paren.trim());
  return Array.from(out).filter((v) => v.length >= 4);
}

export function buildResearchTree(d: ResearchDetail, platformShort: (p: string) => string): TNode {
  const rec = d.record;
  const queries = rec.hunts?.queries ?? [];
  const placedQueries = new Set<string>();
  const tacticsOf = (techs: string[]) => Array.from(new Set(rec.mitre.filter((m) => techs.some((t) => sameTech(m.technique_id, t))).map((m) => m.tactic_id)));

  // Behaviours as the research path models them: attack-path steps plus IoAs no step covers.
  const model = buildPathModel(d, platformShort);
  const behNodes = model.cols[3].filter((n) => n.kind === "behaviour");
  const directOpp = new Map<string, string[]>(); // behaviour path id → opportunity ids (stated links only)
  for (const e of model.edges) {
    if (e.inferred || !e.from.startsWith("beh-") || !e.to.startsWith("opp-")) continue;
    directOpp.set(e.from, [...(directOpp.get(e.from) ?? []), e.to.slice(4)]);
  }
  const mappedOpps = new Set(Array.from(directOpp.values()).flat());
  const groups = groupQueries(rec);

  const leaf = (q: Query, parent: string, tactics: string[]): TNode => {
    placedQueries.add(q.id);
    return {
      id: `${parent}/q-${q.id}`, kind: "detection", label: platformShort(q.platform), sub: q.status, cls: "detection", ref: { t: "query", query: q },
      children: [], search: `${q.id} ${q.platform} ${platformShort(q.platform)} ${q.title} ${q.status}`, tactics, depth: 4,
    };
  };
  const oppNode = (o: Opp, parent: string, tactics: string[]): TNode => {
    const id = `${parent}/o-${o.id}`;
    const t = tactics.length ? tactics : tacticsOf(o.techniques);
    return {
      id, kind: "opportunity", label: o.title, sub: o.id, tag: o.type?.toLowerCase() === "ioa" ? "IoA" : o.type?.toUpperCase(), cls: "opportunity", ref: { t: "opp", opp: o },
      children: queries.filter((q) => q.opportunity_id === o.id).map((q) => leaf(q, id, t)),
      search: `${o.id} ${o.title} ${o.logic} ${o.techniques.join(" ")}`, tactics: t, depth: 3,
    };
  };
  const groupNode = (g: DetectionGroup, parent: string, tactics: string[]): TNode => {
    const id = `${parent}/g-${g.key}`;
    return {
      id, kind: "opportunity", label: g.title, sub: g.key, tag: g.type === "ioc" ? "IoC" : g.type === "vuln" ? "Vuln" : g.type.toUpperCase(), cls: "opportunity",
      ref: { t: "group", group: g }, children: g.queries.map((q) => leaf(q, id, tactics)), search: `${g.key} ${g.title}`, tactics, depth: 3,
    };
  };
  const behaviourNode = (b: (typeof behNodes)[number], parent: string, context?: string): TNode => {
    const data = b.data as Extract<NodeData, { kind: "behaviour" }>;
    const id = `${parent}/${b.id}`;
    const techs = data.step ? [data.step.technique_id] : [];
    const tactics = tacticsOf(techs);
    const opps = (directOpp.get(b.id) ?? []).map((oid) => rec.detection_opportunities.find((o) => o.id === oid)).filter((o): o is Opp => !!o);
    return {
      id, kind: "behaviour", label: b.label, sub: b.sub, tag: b.tag, context, cls: "behaviour",
      ref: data.step ? { t: "step", step: data.step, coveredIoas: data.coveredIoas } : { t: "ioa", ioa: data.ioa! },
      children: opps.map((o) => oppNode(o, id, tactics)), search: `${b.search} ${context ?? ""}`, tactics, depth: 2,
    };
  };
  const stepBeh = (ref: string) => behNodes.find((b) => b.sub === ref);

  const classes: TNode[] = [];
  const cls = (key: ClassKey, sub: string, children: TNode[]): TNode => ({
    id: `c-${key}`, kind: "class", label: CLASS_META[key].label, sub, cls: key, ref: { t: "class", cls: key }, children,
    search: `${CLASS_META[key].label} ${sub}`, tactics: [], depth: 1,
  });

  // CVE: exploitation behaviours, then a vulnerability-exposure behaviour carrying the vuln detections.
  if (rec.vulnerabilities.length) {
    const kids: TNode[] = behNodes.filter((b) => b.tag && EXPLOIT_TECHS.some((t) => sameTech(b.tag!, t))).map((b) => behaviourNode(b, "c-cve"));
    const vulnGroups = groups.filter((g) => g.type === "vuln");
    const cves = rec.vulnerabilities.map((v) => v.cve);
    const expId = "c-cve/exposure";
    kids.push({
      id: expId, kind: "behaviour", label: `Assets still exposed to ${cves.length > 1 ? `${cves[0]} +${cves.length - 1}` : cves[0]}`,
      sub: plural(cves.length, "CVE"), tag: "Exposure", cls: "behaviour", ref: { t: "exposure", cves },
      children: vulnGroups.map((g) => groupNode(g, expId, [])), search: `exposure vulnerable ${cves.join(" ")}`, tactics: [], depth: 2,
    });
    classes.push(cls("cve", `×${cves.length}`, kids));
  }

  // Campaign: the attack paths, step by step.
  if ((rec.classification.includes("campaign") || rec.attack_paths.length > 1) && rec.attack_paths.length) {
    const kids = rec.attack_paths.flatMap((p) => p.steps.map((s) => stepBeh(s.ref)).filter((b): b is NonNullable<typeof b> => !!b).map((b) => behaviourNode(b, "c-campaign", p.name)));
    classes.push(cls("campaign", plural(rec.attack_paths.length, "path"), kids));
  }

  // Threat actors: behaviours whose evidence comes from the sources that attribute the actor.
  if (rec.threat_actors.length) {
    const kids: TNode[] = [];
    for (const b of behNodes) {
      const data = b.data as Extract<NodeData, { kind: "behaviour" }>;
      const srcs = data.step?.source_ids ?? data.ioa?.source_ids ?? [];
      const text = `${b.label} ${data.step?.path_name ?? ""}`.toLowerCase();
      const who = rec.threat_actors.filter((a) => a.source_ids.some((s) => srcs.includes(s)) || [a.name, ...a.aliases].some((n) => n && text.includes(n.toLowerCase())));
      if (who.length) kids.push(behaviourNode(b, "c-actor", who.map((a) => a.name).join(", ")));
    }
    classes.push(cls("actor", `×${rec.threat_actors.length}`, kids));
  }

  // Threat intel: behaviours that use a known malware/tool, the rest of the tooling, and IoC retro-hunts.
  const iocGroups = groups.filter((g) => g.type === "ioc");
  if (rec.malware_tools.length || rec.iocs.length) {
    const kids: TNode[] = [];
    const matched = new Set<string>();
    for (const b of behNodes) {
      const text = b.label.toLowerCase();
      const hits = rec.malware_tools.filter((m) => nameVariants(m.name).some((v) => text.includes(v)));
      if (!hits.length) continue;
      hits.forEach((m) => matched.add(m.name));
      kids.push(behaviourNode(b, "c-intel", hits.map((m) => m.name).join(", ")));
    }
    for (const m of rec.malware_tools.filter((x) => !matched.has(x.name))) {
      kids.push({
        id: `c-intel/mal-${m.name}`, kind: "behaviour", label: `${m.name}: ${m.role}`, tag: m.type, cls: "behaviour", ref: { t: "malware", items: [m] },
        children: [], search: `${m.name} ${m.type} ${m.role}`, tactics: [], depth: 2,
      });
    }
    const byType = new Map<string, IocRow[]>();
    rec.iocs.forEach((i) => byType.set(i.type, [...(byType.get(i.type) ?? []), i]));
    for (const [type, list] of byType) {
      const id = `c-intel/ioc-${type}`;
      const gs = iocGroups.filter((g) => g.key.toLowerCase() === `ioc-${type}` || g.queries.some((q) => q.title.toLowerCase().includes(` ${type} indicator`)));
      kids.push({
        id, kind: "behaviour", label: `Known ${IOC_TYPE_LABEL[type] ?? type} indicators (${list.length})`, tag: "IoC", cls: "behaviour", ref: { t: "iocs", iocType: type, iocs: list },
        children: gs.map((g) => groupNode(g, id, [])), search: `ioc ${type} ${list.map((i) => i.value).join(" ")}`, tactics: [], depth: 2,
      });
    }
    // IoC groups whose type has no rows left (e.g. every indicator excluded) still need a home.
    const orphanIoc = iocGroups.filter((g) => !kids.some((k) => k.children.some((c) => c.ref.t === "group" && c.ref.group.key === g.key)));
    if (orphanIoc.length) kids.push({
      id: "c-intel/ioc-other", kind: "behaviour", label: "Known indicators", tag: "IoC", cls: "behaviour", ref: { t: "iocs", iocType: "", iocs: [] },
      children: orphanIoc.map((g) => groupNode(g, "c-intel/ioc-other", [])), search: "ioc indicators", tactics: [], depth: 2,
    });
    const nMal = rec.malware_tools.length, nIoc = rec.iocs.length;
    classes.push(cls("intel", [nMal ? plural(nMal, "tool") : "", nIoc ? plural(nIoc, "IoC") : ""].filter(Boolean).join(" · "), kids));
  }

  // TTPs: every behaviour, then techniques no behaviour describes, then what has no behaviour at all.
  {
    const kids: TNode[] = behNodes.map((b) => behaviourNode(b, "c-ttp"));
    const described = behNodes.map((b) => b.tag).filter((t): t is string => !!t && t !== "IoA");
    const seen = new Set<string>();
    for (const m of rec.mitre) {
      if (seen.has(m.technique_id) || described.some((t) => t === m.technique_id)) continue;
      seen.add(m.technique_id);
      const id = `c-ttp/t-${m.technique_id}`;
      const tactics = Array.from(new Set(rec.mitre.filter((x) => x.technique_id === m.technique_id).map((x) => x.tactic_id)));
      const generic = groups.filter((g) => !g.opportunityId && (g.type === "ttp" || g.type === "ioa") && g.queries.some((q) => q.techniques.some((t) => sameTech(t, m.technique_id))));
      kids.push({
        id, kind: "behaviour", label: m.procedure || m.sub_technique || m.technique, tag: m.technique_id, sub: m.tactic, cls: "behaviour", ref: { t: "technique", techId: m.technique_id },
        children: generic.map((g) => groupNode(g, id, tactics)), search: `${m.technique_id} ${m.technique} ${m.sub_technique} ${m.procedure}`, tactics, depth: 2,
      });
    }
    const unmappedOpps = rec.detection_opportunities.filter((o) => !mappedOpps.has(o.id));
    const unmapped: TNode = {
      id: "c-ttp/unmapped", kind: "behaviour", label: "Unmapped behaviour", sub: "no matching step", tag: "Unmapped", cls: "behaviour", ref: { t: "unmapped" },
      children: unmappedOpps.map((o) => oppNode(o, "c-ttp/unmapped", [])), search: "unmapped behaviour", tactics: [], depth: 2,
    };
    const nTech = new Set(rec.mitre.map((m) => m.technique_id)).size;
    const ttp = cls("ttp", `×${nTech}`, kids);
    classes.push(ttp);
    // Anything not placed yet (a generic hunt with no technique match, a vuln query with no CVE class) lands here.
    const rest = groups.filter((g) => g.queries.some((q) => !placedQueries.has(q.id)));
    rest.forEach((g) => unmapped.children.push(groupNode({ ...g, queries: g.queries.filter((q) => !placedQueries.has(q.id)) }, unmapped.id, [])));
    if (unmapped.children.length) ttp.children.push(unmapped);
  }

  return {
    id: "root", kind: "subject", label: rec.title.split(":")[0] || rec.title, sub: d.id, cls: "subject", ref: { t: "subject" },
    children: classes, search: `${rec.title} ${d.id}`, tactics: [], depth: 0,
  };
}

/** Ids of nodes with children, for "expand all". */
export function branchIds(root: TNode): string[] {
  const out: string[] = [];
  const walk = (n: TNode) => { if (n.children.length) out.push(n.id); n.children.forEach(walk); };
  walk(root);
  return out;
}

/** Default: collapsed below level 3 (subject and classifications open, behaviours shown collapsed). */
export const defaultExpanded = (root: TNode) => new Set(["root", ...root.children.map((c) => c.id)]);

/** Tree canvas opening state: every classification visible, only the first non-empty one expanded (the tree is an
 *  accordion, so this is the same state a click produces, and it keeps the canvas short enough to read). */
export const treeDefaultExpanded = (root: TNode) => {
  const first = root.children.find((c) => c.children.length);
  return new Set(["root", ...(first ? [first.id] : [])]);
};

/** Accordion toggle: opening a node closes its open siblings; clicking the only open sibling closes it. */
export function accordion(expanded: Set<string>, node: TNode, parent: TNode | null): Set<string> {
  const next = new Set(expanded);
  const siblings = (parent?.children ?? []).filter((s) => s.id !== node.id && s.children.length);
  const openSiblings = siblings.filter((s) => next.has(s.id));
  const closeBranch = (n: TNode) => { next.delete(n.id); n.children.forEach(closeBranch); };
  if (next.has(node.id) && !openSiblings.length) closeBranch(node);
  else { next.add(node.id); openSiblings.forEach(closeBranch); }
  return next;
}

export function findPath(root: TNode, id: string): TNode[] {
  const trail: TNode[] = [];
  const walk = (n: TNode): boolean => {
    trail.push(n);
    if (n.id === id || n.children.some(walk)) return true;
    trail.pop();
    return false;
  };
  walk(root);
  return trail;
}

/** Distinct underlying items per level (a step shown under three classes counts once). */
export function levelCounts(root: TNode) {
  const beh = new Set<string>(), opp = new Set<string>(), det = new Set<string>();
  const key = (n: TNode) => n.id.split("/").pop()!;
  const walk = (n: TNode) => {
    if (n.kind === "behaviour") beh.add(key(n));
    if (n.kind === "opportunity") opp.add(key(n));
    if (n.kind === "detection") det.add(key(n));
    n.children.forEach(walk);
  };
  walk(root);
  return { classes: root.children.length, behaviours: beh.size, opportunities: opp.size, detections: det.size };
}

export interface TreeFilter { cls?: string; tactic?: string; platform?: string; status?: string; text?: string }

/** Prune the tree to what matches; ancestors of a match stay, a text match keeps its whole branch. */
export function filterTree(root: TNode, f: TreeFilter): TNode {
  const text = f.text?.trim().toLowerCase();
  const leafFilter = !!(f.platform || f.status);
  const hit = (n: TNode) => !!text && `${n.label} ${n.sub ?? ""} ${n.tag ?? ""} ${n.context ?? ""} ${n.search}`.toLowerCase().includes(text);
  const prune = (n: TNode, inherited: boolean): TNode | null => {
    if (n.kind === "class" && f.cls && n.cls !== f.cls) return null;
    if (n.kind === "behaviour" && f.tactic && !n.tactics.includes(f.tactic)) return null;
    const textOk = !text || inherited || hit(n);
    if (n.kind === "detection") {
      const q = (n.ref as Extract<TRef, { t: "query" }>).query;
      if (f.platform && q.platform !== f.platform) return null;
      if (f.status && q.status !== f.status) return null;
      return textOk ? n : null;
    }
    const kids = n.children.map((c) => prune(c, textOk && !!text)).filter((c): c is TNode => !!c);
    const selfOk = textOk && !leafFilter && (!f.tactic || n.kind !== "class");
    if (n.kind === "subject" || kids.length || selfOk) return { ...n, children: kids };
    return null;
  };
  return prune(root, false) ?? { ...root, children: [] };
}

/** Counts of descendants per level, for List view rows. */
export function descendantCounts(n: TNode) {
  const c = levelCounts({ ...n, children: n.children });
  return { behaviours: c.behaviours, opportunities: c.opportunities, detections: c.detections };
}
