"use client";

import { AttackChip, Badge, Chip } from "@/components/ui/badges";
import { Drawer } from "@/components/ui/overlay";
import { DATA_SOURCES, IOC_TYPE_LABEL } from "@/lib/constants";
import type { ResearchRecord } from "@/lib/types";
import { Quote, SourceRefs } from "../detail/common";
import { SourceChips } from "../provenance";
import { QueryBlock } from "../query-block";
import { CLASS_META, type TNode } from "./model";

const KIND_LABEL: Record<TNode["kind"], string> = {
  subject: "Subject", class: "Classification", behaviour: "Attack behaviour", opportunity: "Detection opportunity", detection: "Detection",
};

/** Colour of a node: its classification for level 2, the level colour below it. */
export const nodeColor = (n: TNode) => (n.kind === "class" ? CLASS_META[n.ref.t === "class" ? n.ref.cls : "ttp"].color
  : n.kind === "subject" ? "var(--btn-primary)" : `var(--cls-${n.kind})`);

/** Right-side detail drawer shared by Tree and List views; prev/next walk the node's siblings. */
export function NodeDrawer({ node, siblings, onSelect, onClose, rec, canEdit }:
  { node: TNode | null; siblings: TNode[]; onSelect: (n: TNode) => void; onClose: () => void; rec: ResearchRecord; canEdit: boolean }) {
  const i = node ? siblings.findIndex((s) => s.id === node.id) : -1;
  const q = node?.ref.t === "query" ? node.ref.query : null;
  return (
    <Drawer open={!!node} onClose={onClose} width={node?.kind === "detection" || node?.kind === "opportunity" ? 640 : 480}
      title={q ? `${node!.label} query` : node?.label ?? ""}
      subtitle={node ? <span className="flex items-center gap-2"><span className="size-2 rounded-full" style={{ background: nodeColor(node) }} />{KIND_LABEL[node.kind]}{node.sub ? ` · ${node.sub}` : ""}</span> : null}
      onPrev={i > 0 ? () => onSelect(siblings[i - 1]) : undefined}
      onNext={i >= 0 && i < siblings.length - 1 ? () => onSelect(siblings[i + 1]) : undefined}>
      {node && <NodeDetails n={node} rec={rec} canEdit={canEdit} />}
    </Drawer>
  );
}

function NodeDetails({ n, rec, canEdit }: { n: TNode; rec: ResearchRecord; canEdit: boolean }) {
  const sources = Object.fromEntries(rec.sources.map((s) => [s.id, s]));
  const r = n.ref;
  const attack = (id: string) => <a href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer" className="prose-link text-[14px]">View {id} on attack.mitre.org</a>;
  const mitreRows = (id: string) => rec.mitre.filter((x) => x.technique_id === id).map((x, k) => (
    <div key={k} className="rounded-md border border-line p-3">
      <p className="text-caption text-fg-muted">{x.tactic} · {x.confidence} confidence</p>
      <p className="mt-1 text-[14px]">{x.procedure}</p>
      {x.evidence_quote && <p className="mt-2 text-[14px]"><Quote>{x.evidence_quote}</Quote><SourceRefs ids={x.source_ids} sources={sources} /></p>}
    </div>
  ));

  switch (r.t) {
    case "query": {
      const siblings = rec.hunts.queries.filter((x) => (x.group && x.group === r.query.group) || (r.query.opportunity_id && x.opportunity_id === r.query.opportunity_id));
      return <QueryBlock title={r.query.title} refId={r.query.opportunity_id ?? r.query.group ?? r.query.id} queries={siblings.length ? siblings : [r.query]} defaultPlatform={r.query.platform} canEdit={canEdit} />;
    }
    case "opp": {
      const o = r.opp;
      const qs = rec.hunts.queries.filter((x) => x.opportunity_id === o.id);
      return (
        <div className="space-y-4">
          <p className="text-[14px]">{o.logic}</p>
          <div className="flex flex-wrap gap-1.5">{o.techniques.map((t) => <AttackChip key={t} id={t} />)}</div>
          <p className="text-body-sm"><span className="text-fg-muted">Data sources: </span>{o.data_sources.map((x) => DATA_SOURCES[x] ?? x).join(", ")}</p>
          {o.fp_notes && <p className="text-body-sm"><span className="text-fg-muted">False positives: </span>{o.fp_notes}</p>}
          <SourceChips ids={o.source_ids ?? []} sources={sources} />
          {qs.length > 0 ? <QueryBlock title={o.title} refId={o.id} queries={qs} canEdit={canEdit} /> : <p className="text-body-sm text-fg-muted">No queries generated for this opportunity yet.</p>}
        </div>
      );
    }
    case "group": {
      const g = r.group;
      return (
        <div className="space-y-4">
          <p className="text-[14px]">{g.type === "ioc" ? "Retro-hunt for the indicators in this research across the look-back window." : g.type === "vuln" ? "Finds assets that still run a vulnerable version." : "Wider technique hunt that is not tied to one detection opportunity."}</p>
          <SourceChips ids={g.sourceIds} sources={sources} />
          <QueryBlock title={g.title} refId={g.key} queries={g.queries} canEdit={canEdit} />
        </div>
      );
    }
    case "step": {
      const s = r.step;
      return (
        <div className="space-y-4">
          <code className="block rounded-sm bg-code p-3 font-mono text-mono break-words">{s.behaviour}</code>
          <p className="text-body-sm"><span className="text-fg-muted">Attack path: </span>{s.path_id} · {s.path_name}</p>
          {n.context && <p className="text-body-sm"><span className="text-fg-muted">Attributed to: </span>{n.context}</p>}
          <AttackChip id={s.technique_id} name={rec.mitre.find((m) => m.technique_id === s.technique_id)?.sub_technique || rec.mitre.find((m) => m.technique_id === s.technique_id)?.technique} tactic={rec.mitre.find((m) => m.technique_id === s.technique_id)?.tactic} />
          {mitreRows(s.technique_id)}
          {r.coveredIoas.length > 0 && <p className="text-body-sm"><span className="text-fg-muted">Also covers: </span>{r.coveredIoas.map((i) => `${i.id} ${i.description}`).join("; ")}</p>}
          <SourceChips ids={s.source_ids} sources={sources} />
          {attack(s.technique_id)}
        </div>
      );
    }
    case "ioa":
      return (
        <div className="space-y-4">
          <code className="block rounded-sm bg-code p-3 font-mono text-mono break-words">{r.ioa.description}</code>
          <Badge>{r.ioa.kind.replace(/_/g, " ")}</Badge>
          <SourceChips ids={r.ioa.source_ids} sources={sources} />
        </div>
      );
    case "technique":
      return <div className="space-y-4"><AttackChip id={r.techId} name={rec.mitre.find((m) => m.technique_id === r.techId)?.technique} />{mitreRows(r.techId)}{attack(r.techId)}</div>;
    case "malware":
      return (
        <div className="space-y-3 text-[14px]">
          {r.items.map((m) => (
            <div key={m.name} className="rounded-md border border-line p-3">
              <p className="font-semibold">{m.name} <Badge>{m.type}</Badge></p>
              <p className="mt-1">{m.role}</p>
              <div className="mt-2"><SourceChips ids={m.source_ids} sources={sources} /></div>
            </div>
          ))}
          <p className="text-body-sm text-fg-muted">No attack-path step names this tool, so it has no detection opportunity of its own.</p>
        </div>
      );
    case "iocs":
      return (
        <div className="space-y-2 text-[14px]">
          <p className="text-fg-muted">{r.iocs.length} {IOC_TYPE_LABEL[r.iocType] ?? r.iocType} indicator{r.iocs.length === 1 ? "" : "s"}{n.children.length ? " · retro-hunt queries below" : " · no retro-hunt query for this type"}</p>
          <ul className="divide-y divide-[var(--border-subtle)]">
            {r.iocs.map((i) => <li key={i.value} className="py-1.5"><code className="font-mono text-mono-sm break-all">{i.value}</code><div className="text-caption text-fg-muted">{i.role}</div></li>)}
          </ul>
        </div>
      );
    case "exposure":
      return (
        <div className="space-y-3 text-[14px]">
          {rec.vulnerabilities.filter((v) => r.cves.includes(v.cve)).map((v) => (
            <div key={v.cve} className="rounded-md border border-line p-3">
              <p className="font-mono font-semibold">{v.cve}{v.cvss ? <span className="ml-2 font-sans text-caption text-fg-muted">CVSS {v.cvss}{v.epss != null ? ` · EPSS ${v.epss}` : ""}{v.kev_added ? " · KEV" : ""}</span> : null}</p>
              {v.description && <p className="mt-1">{v.description}</p>}
              {v.affected_products.length > 0 && <p className="mt-1 text-body-sm"><span className="text-fg-muted">Affected: </span>{v.affected_products.join(", ")}</p>}
              {v.fixed_versions.length > 0 && <p className="text-body-sm"><span className="text-fg-muted">Fixed in: </span>{v.fixed_versions.join(", ")}</p>}
            </div>
          ))}
        </div>
      );
    case "unmapped":
      return <p className="text-[14px]">Detection opportunities and hunts whose behaviour is not one of the extracted attack-path steps or IoAs. Map them in the report editor to place them in the tree.</p>;
    case "class":
      return <ClassDetails cls={r.cls} n={n} rec={rec} sources={sources} />;
    default:
      return (
        <div className="space-y-2 text-[14px]">
          <p>{rec.title}</p>
          <div className="flex flex-wrap gap-1.5">{rec.classification.map((c) => <Chip key={c}>{c.replace("_", " ")}</Chip>)}</div>
          <Badge>{rec.mitre.length} technique mappings</Badge>
        </div>
      );
  }
}

function ClassDetails({ cls, n, rec, sources }: { cls: string; n: TNode; rec: ResearchRecord; sources: Record<string, ResearchRecord["sources"][number]> }) {
  const intro = <p className="text-body-sm text-fg-muted">{n.children.length} attack behaviour{n.children.length === 1 ? "" : "s"} under this classification. Click the node to expand them.</p>;
  if (cls === "actor") return (
    <div className="space-y-3 text-[14px]">
      {intro}
      {rec.threat_actors.map((a) => (
        <div key={a.name} className="rounded-md border border-line p-3">
          <p className="font-semibold">{a.name}</p>
          {a.aliases.length > 0 && <p className="text-body-sm text-fg-muted">aka {a.aliases.join(", ")}</p>}
          <p className="mt-1 text-body-sm">{[a.origin, a.motivation.join(", "), `${a.attribution_confidence} attribution confidence`].filter(Boolean).join(" · ")}</p>
          <div className="mt-2"><SourceChips ids={a.source_ids} sources={sources} /></div>
        </div>
      ))}
    </div>
  );
  if (cls === "cve") return (
    <div className="space-y-2 text-[14px]">
      {intro}
      {rec.vulnerabilities.map((v) => <p key={v.cve}><span className="font-mono font-semibold">{v.cve}</span> <span className="text-fg-muted">CVSS {v.cvss}{v.kev_added ? " · KEV" : ""}</span></p>)}
    </div>
  );
  if (cls === "campaign") return (
    <div className="space-y-3 text-[14px]">
      {intro}
      {rec.attack_paths.map((p) => <div key={p.id}><p className="font-semibold">{p.id} · {p.name}</p><ol className="mt-1 list-decimal space-y-0.5 pl-5">{p.steps.map((s) => <li key={s.ref}>{s.behaviour} <span className="font-mono text-mono-sm text-fg-muted">{s.technique_id}</span></li>)}</ol></div>)}
    </div>
  );
  if (cls === "intel") return (
    <div className="space-y-2 text-[14px]">
      {intro}
      <ul className="space-y-1">{rec.malware_tools.map((m) => <li key={m.name}><span className="font-semibold">{m.name}</span> <span className="text-fg-muted">({m.type}) {m.role}</span></li>)}</ul>
      <p className="text-body-sm text-fg-muted">{rec.iocs.length} indicators of compromise</p>
    </div>
  );
  return <div className="space-y-2 text-[14px]">{intro}<p>{new Set(rec.mitre.map((m) => m.technique_id)).size} ATT&CK techniques mapped.</p></div>;
}
