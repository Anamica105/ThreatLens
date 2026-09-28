"use client";

import clsx from "clsx";
import { Check, Pencil, Plus, Trash2, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { HORIZON, SEVERITY, SEVERITIES } from "@/lib/constants";
import { utc } from "@/lib/format";
import type { MitreRow, ResearchRecord, ResultStatus, Severity } from "@/lib/types";
import { useApp, useWsHref } from "../../providers";
import { AttackChip, Avatar, Badge, Chip, ConfidenceBadge, GeneratedBadge, ResultPill, SeverityBadge, TlpBadge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { useToast } from "../../ui/feedback";
import { Checkbox, Field, Input, Select, Textarea } from "../../ui/forms";
import { DefinitionList, Panel } from "../../ui/layout";
import { Dialog } from "../../ui/overlay";
import { patch, post, put } from "@/lib/api";
import { ClaimConflict } from "../claim-conflict";
import { IocValue } from "../ioc-value";
import { SectionHeading, SourceRefs, type DetailProps, Quote } from "./common";

const TOC = [
  ["executive-summary", "Executive summary"], ["impact", "Impact"], ["recommendations", "Recommendations"], ["result", "Result"],
  ["vulnerabilities", "Vulnerabilities"], ["actors", "Threat actors"], ["attack-paths", "Attack paths"], ["mitre", "MITRE ATT&CK"],
  ["ioas", "Indicators of attack"], ["tools", "Tools used"], ["workflow", "Workflow"], ["hunts", "Hunts"], ["iocs", "IoCs"],
  ["industries", "Industries"], ["timeline", "Timeline"],
] as const;

export function ReportTab({ d, reload, patchRecord, canEdit, ws, tacticFilter }: DetailProps & { tacticFilter: string | null }) {
  const rec = d.record;
  const sources = useMemo(() => Object.fromEntries(rec.sources.map((s) => [s.id, s])), [rec.sources]);
  const [active, setActive] = useState<string>("executive-summary");
  const [editing, setEditing] = useState<null | "summary" | "impact" | "recs" | "title">(null);
  const toast = useToast();
  const wsHref = useWsHref();

  useEffect(() => {
    const els = TOC.map(([id]) => document.getElementById(id)).filter(Boolean) as HTMLElement[];
    const obs = new IntersectionObserver((entries) => {
      const vis = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      if (vis[0]) setActive(vis[0].target.id);
    }, { rootMargin: "-120px 0px -60% 0px" });
    els.forEach((e) => obs.observe(e));
    return () => obs.disconnect();
  }, [rec]);

  const setConflict = async (i: number, status: string) => {
    try {
      await patch(`/api/research/${d.id}/conflicts/${i}`, { status });
      toast({ tone: "success", message: `Claim marked ${status}` });
      reload();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
  };
  const approve = async (section: string) => {
    await post(`/api/research/${d.id}/review`, { section, state: "approved" });
    reload();
  };
  const review = rec.review ?? {};
  const ReviewBar = ({ section }: { section: string }) => review[section] && review[section] !== "approved" ? (
    <>
      <GeneratedBadge state={review[section]} />
      {canEdit && <Button size="sm" variant="tertiary" icon={<Check />} onClick={() => approve(section)}>Approve</Button>}
    </>
  ) : null;

  const mitre = tacticFilter ? rec.mitre.filter((m) => m.tactic_id === tacticFilter) : rec.mitre;
  const queries = rec.hunts?.queries?.filter((q) => q.origin !== "reference") ?? [];
  const wsGaps = (rec.coverage_gaps ?? []).filter((g) => ws === "all" || g.workspace_id === ws);

  return (
    <div className="grid gap-8 xl:grid-cols-[200px_minmax(0,1fr)_320px] lg:grid-cols-[minmax(0,1fr)_300px]">
      <nav aria-label="On this page" className="hidden xl:block">
        <div className="sticky top-32">
          <div className="mb-2 text-caption font-semibold text-fg-muted">On this page</div>
          <ul className="space-y-0.5 border-l border-line">
            {TOC.map(([id, label]) => (
              <li key={id}>
                <a href={`#${id}`} className={clsx("-ml-px block border-l-2 py-1 pl-3 text-body-sm", active === id ? "border-accent font-semibold text-fg" : "border-transparent text-fg-muted hover:text-fg")}>{label}</a>
              </li>
            ))}
          </ul>
        </div>
      </nav>

      <article className="min-w-0 space-y-10">
        {rec.demo_note && <p className="rounded-md border border-line bg-subtle px-4 py-3 text-body-sm text-fg-strong">{rec.demo_note}</p>}
        <section>
          <SectionHeading id="executive-summary" actions={<>
            <ReviewBar section="executive_summary" />
            {canEdit && <Button size="sm" variant="tertiary" icon={<Pencil />} onClick={() => setEditing("summary")}>Edit</Button>}
          </>}>Executive summary</SectionHeading>
          <div className="reading space-y-4 text-body-lg">
            {rec.executive_summary.split(/\n\n+/).map((p, i) => <p key={i}>{p}</p>)}
          </div>
        </section>

        <section>
          <SectionHeading id="impact" actions={<>
            <ReviewBar section="impact" />
            {canEdit && <Button size="sm" variant="tertiary" icon={<Pencil />} onClick={() => setEditing("impact")}>Edit</Button>}
          </>}>Impact</SectionHeading>
          <div className="reading space-y-3 text-body-lg">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={rec.impact.severity} />
              {(["confidentiality", "integrity", "availability"] as const).map((k) => (
                <Badge key={k} tone={rec.impact.cia[k] ? "neutral" : "muted"}>{rec.impact.cia[k] ? "✓" : "–"} {k.charAt(0).toUpperCase() + k.slice(1)}</Badge>
              ))}
            </div>
            <p>{rec.impact.business_impact}</p>
            {rec.impact.blast_radius && <p><span className="text-fg-muted">Blast radius: </span>{rec.impact.blast_radius}</p>}
          </div>
          {rec.conflicts.length > 0 && (
            <div className="mt-5 space-y-3">
              {rec.conflicts.map((c, i) => <ClaimConflict key={i} c={c} sources={sources} onStatus={canEdit ? (s) => setConflict(i, s) : undefined} />)}
            </div>
          )}
          {rec.claims?.some((c) => !c.source_ids?.length) && (
            <p className="mt-3 flex items-center gap-1.5 text-body-sm text-danger"><TriangleAlert className="size-4" />Unsupported claims must be edited before publishing.</p>
          )}
        </section>

        <section>
          <SectionHeading id="recommendations" actions={<>
            <ReviewBar section="recommendations" />
            {canEdit && <Button size="sm" variant="tertiary" icon={<Pencil />} onClick={() => setEditing("recs")}>Edit</Button>}
          </>}>Recommendations</SectionHeading>
          {rec.patching_insufficient && (
            <div className="mb-4 flex items-center gap-2 rounded-md border px-4 py-2.5 text-[14px] font-semibold" style={{ background: "var(--warning-soft)", borderColor: "var(--warning-border)", color: "var(--warning)" }}>
              <TriangleAlert className="size-5" /> Patching alone is insufficient for this threat.
            </div>
          )}
          <div className="reading space-y-5">
            {(["immediate", "short_term", "strategic"] as const).map((h) => {
              const items = rec.recommendations.filter((r) => r.horizon === h);
              if (!items.length) return null;
              return (
                <div key={h}>
                  <h3 className="mb-2 text-h3 font-semibold">{HORIZON[h]}</h3>
                  <ul className="space-y-2">
                    {items.map((r, i) => (
                      <li key={i} className="flex gap-3 text-body-lg">
                        <span className="mt-1.5 size-3.5 shrink-0 rounded-xs border border-line-hover" aria-hidden />
                        <span>{r.action}<SourceRefs ids={r.source_ids} sources={sources} /> <Chip className="ml-1 align-middle">{r.owner_role}</Chip></span>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </section>

        <section>
          <SectionHeading id="result">Result</SectionHeading>
          <ResultsTable d={d} ws={ws} reload={reload} canEdit={canEdit} />
        </section>

        {rec.vulnerabilities.length > 0 && (
          <section>
            <SectionHeading id="vulnerabilities">Vulnerabilities</SectionHeading>
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="tl-table tl-compact w-full">
                <thead><tr><th>CVE</th><th className="num">CVSS</th><th>KEV added</th><th>Affected products</th><th>Patch</th><th>Sources</th></tr></thead>
                <tbody>
                  {rec.vulnerabilities.map((v) => (
                    <tr key={v.cve}>
                      <td><a href={`https://nvd.nist.gov/vuln/detail/${v.cve}`} target="_blank" rel="noopener noreferrer" className="font-mono text-accent-text hover:underline">{v.cve}</a></td>
                      <td className="num font-semibold">{v.cvss || "—"}</td>
                      <td>{v.kev_added ?? <span className="text-fg-faint">—</span>}</td>
                      <td className="min-w-[220px]">{v.affected_products.join(", ") || "—"}</td>
                      <td className="font-mono text-mono-sm">{v.patch_kb.join(", ") || "—"}</td>
                      <td><SourceRefs ids={v.source_ids} sources={sources} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {rec.threat_actors.length > 0 && (
          <section>
            <SectionHeading id="actors">Threat actors</SectionHeading>
            <div className="grid gap-3 md:grid-cols-2">
              {rec.threat_actors.map((a) => (
                <div key={a.name} className="rounded-md border border-line bg-surface p-4">
                  <div className="flex items-center gap-2">
                    <Link href={wsHref(`/library/actors/${a.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`)} className="text-h4 font-semibold hover:underline">{a.name}</Link>
                    <ConfidenceBadge level={a.attribution_confidence} />
                  </div>
                  {a.aliases.length > 0 && <p className="mt-1 text-body-sm text-fg-muted">Also known as {a.aliases.join(", ")}</p>}
                  <p className="mt-2 text-body-sm">{a.origin || "Origin unknown"} · {a.motivation.join(", ") || "motivation unknown"}<SourceRefs ids={a.source_ids} sources={sources} /></p>
                </div>
              ))}
            </div>
          </section>
        )}

        {rec.attack_paths.length > 0 && (
          <section>
            <SectionHeading id="attack-paths" actions={<ReviewBar section="attack_paths" />}>Attack paths</SectionHeading>
            <div className="space-y-4">
              {rec.attack_paths.map((p) => (
                <div key={p.id} className="rounded-md border border-line bg-surface p-4">
                  <h3 className="text-h4 font-semibold"><span className="font-mono text-mono-sm text-fg-muted">{p.id}</span> · {p.name}</h3>
                  <ol className="mt-3 space-y-2">
                    {p.steps.map((s) => (
                      <li key={s.ref} className="flex items-start gap-3">
                        <span className="mt-0.5 w-12 shrink-0 font-mono text-mono-sm text-fg-muted">{s.ref}</span>
                        <span className="flex-1 text-[14px]">{s.behaviour}<SourceRefs ids={s.source_ids} sources={sources} /></span>
                        <AttackChip id={s.technique_id} />
                      </li>
                    ))}
                  </ol>
                </div>
              ))}
            </div>
          </section>
        )}

        <section>
          <SectionHeading id="mitre" actions={<>
            {tacticFilter && <Badge tone="accent">Filtered to one tactic</Badge>}
            <ReviewBar section="mitre" />
          </>}>MITRE ATT&amp;CK</SectionHeading>
          <MitreTable rows={mitre} sources={sources} canEdit={canEdit} onRemove={(tid) => patchRecord({ mitre: rec.mitre.filter((m) => m.technique_id !== tid) }, `Removed ${tid}`)} />
        </section>

        {rec.ioas?.length > 0 && (
          <section>
            <SectionHeading id="ioas">Indicators of attack</SectionHeading>
            <ul className="space-y-2">
              {rec.ioas.map((i) => (
                <li key={i.id} className="flex items-start gap-3 rounded-md border border-line bg-surface px-4 py-3">
                  <Badge>{i.kind.replace("_", " ")}</Badge>
                  <code className="flex-1 font-mono text-mono break-words">{i.description}</code>
                  <SourceRefs ids={i.source_ids} sources={sources} />
                </li>
              ))}
            </ul>
          </section>
        )}

        <section>
          <SectionHeading id="tools">Tools used</SectionHeading>
          {rec.tools_used.length ? (
            <ul className="flex flex-wrap gap-2">{rec.tools_used.map((t) => <li key={t.name}><Chip title={t.detail}>{t.name}</Chip></li>)}</ul>
          ) : <p className="text-fg-muted">None recorded.</p>}
          {rec.malware_tools.length > 0 && (
            <>
              <h3 className="mt-5 mb-2 text-h3 font-semibold">Attacker malware and tools</h3>
              <div className="overflow-x-auto rounded-md border border-line">
                <table className="tl-table tl-compact w-full">
                  <thead><tr><th>Name</th><th>Type</th><th>Role in the chain</th><th>Sources</th></tr></thead>
                  <tbody>{rec.malware_tools.map((m) => (
                    <tr key={m.name}>
                      <td><Link className="hover:underline" href={wsHref(`/library/malware/${m.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`)}>{m.name}</Link></td>
                      <td><Badge>{m.type}</Badge></td><td>{m.role}</td><td><SourceRefs ids={m.source_ids} sources={sources} /></td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </>
          )}
        </section>

        <section>
          <SectionHeading id="workflow">Workflow</SectionHeading>
          <ol className="space-y-0">
            {rec.workflow.map((w, i) => (
              <li key={i} className="relative flex gap-3 pb-4">
                {i < rec.workflow.length - 1 && <span className="absolute top-4 bottom-0 left-[3.5px] w-px bg-[var(--border-default)]" aria-hidden />}
                <span className="relative mt-1.5 size-2 shrink-0 rounded-full" style={{ background: w.actor === "hunter" ? "var(--info)" : "var(--accent)" }} />
                <div className="flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-3">
                    <span className="text-[14px] font-semibold">{w.step}</span>
                    <span className="text-caption text-fg-muted">{w.actor === "hunter" ? "Hunter" : "Agent"}{w.notes ? ` · ${w.notes}` : ""}</span>
                    <span className="ml-auto text-caption text-fg-muted tabular">{w.finished_at ? utc(w.finished_at) : ""}</span>
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <section>
          <SectionHeading id="hunts" actions={<Link href="?tab=hunts" className="text-[14px] font-semibold text-accent-text hover:underline">Open Hunts tab</Link>}>Hunts</SectionHeading>
          <p className="reading text-body-lg">
            {queries.filter((q) => q.type === "ioa").length} IoA, {queries.filter((q) => q.type === "ioc").length} IoC, {queries.filter((q) => q.type === "vuln").length} vulnerability
            and {queries.filter((q) => q.type === "ttp").length} TTP queries across {rec.hunts.platforms.length} platform{rec.hunts.platforms.length === 1 ? "" : "s"}, with a {rec.hunts.lookback_days}-day look-back.
          </p>
          {wsGaps.length > 0 && (
            <div className="mt-3 rounded-md border px-4 py-3" style={{ background: "var(--warning-soft)", borderColor: "var(--warning-border)" }}>
              <div className="flex items-center gap-2 text-h4 font-semibold" style={{ color: "var(--warning)" }}><TriangleAlert className="size-5" />Coverage gaps</div>
              <ul className="mt-1 list-disc pl-6 text-[14px]">
                {Array.from(new Set(wsGaps.map((g) => g.detail))).map((g) => <li key={g}>{g}</li>)}
              </ul>
            </div>
          )}
        </section>

        <section>
          <SectionHeading id="iocs" actions={<Link href="?tab=iocs" className="text-[14px] font-semibold text-accent-text hover:underline">All {rec.iocs.length} IoCs</Link>}>IoCs</SectionHeading>
          {rec.iocs.length ? (
            <ul className="space-y-1.5">
              {rec.iocs.filter((i) => i.verdict === "malicious" || i.verdict === "suspicious").slice(0, 10).map((i) => (
                <li key={i.type + i.value}><IocValue type={i.type} value={i.value} verdict={i.verdict} sources={i.source_ids.length} publishers={i.source_ids.map((s) => sources[s]?.publisher ?? s)} /></li>
              ))}
            </ul>
          ) : <p className="text-fg-muted">This threat is described by behaviour only. See the IoA queries.</p>}
        </section>

        <section>
          <SectionHeading id="industries">Industries</SectionHeading>
          <div className="flex flex-wrap gap-2">
            {rec.industries.map((i) => <Chip key={i.industry} title={`${i.evidence} · ${i.source_ids.join(", ")}`}>{i.industry} <span className="text-fg-muted">· {i.evidence}</span></Chip>)}
            {!rec.industries.length && <p className="text-fg-muted">No targeted industries identified.</p>}
          </div>
          {rec.geography?.length > 0 && <p className="mt-3 text-[14px]"><span className="text-fg-muted">Regions: </span>{rec.geography.join(", ")}</p>}
        </section>

        {rec.timeline.length > 0 && (
          <section>
            <SectionHeading id="timeline">Timeline</SectionHeading>
            <ol>
              {rec.timeline.map((t, i) => (
                <li key={i} className="relative flex gap-3 pb-4">
                  {i < rec.timeline.length - 1 && <span className="absolute top-4 bottom-0 left-[3.5px] w-px bg-[var(--border-default)]" aria-hidden />}
                  <span className="relative mt-1.5 size-2 shrink-0 rounded-full bg-[var(--g-400)]" />
                  <span className="w-24 shrink-0 tabular text-caption text-fg-muted">{t.date}</span>
                  <span className="text-[14px]">{t.event}<SourceRefs ids={t.source_ids} sources={sources} /></span>
                </li>
              ))}
            </ol>
          </section>
        )}
      </article>

      <aside className="min-w-0 space-y-4 lg:sticky lg:top-32 lg:self-start">
        <Panel title="Details">
          <DefinitionList items={[
            { label: "Report ID", value: <span className="font-mono text-mono">{d.id}</span> },
            { label: "Version", value: `v${d.version}` },
            { label: "Severity", value: <SeverityBadge severity={d.severity} /> },
            { label: "Confidence", value: <ConfidenceBadge level={d.confidence} /> },
            { label: "TLP", value: <TlpBadge tlp={d.tlp} /> },
            { label: "First reported", value: rec.timeline[0]?.date ?? "—" },
            { label: "Last updated", value: utc(d.updated_at) },
            { label: "Analyst", value: d.author ? <span className="flex items-center gap-2"><Avatar initials={d.author.initials} size={20} />{d.author.name}</span> : "—" },
            { label: "Reviewer", value: d.reviewed_by ? <span className="flex items-center gap-2"><Avatar initials={d.reviewed_by.initials} size={20} />{d.reviewed_by.name}</span> : "Not yet reviewed" },
            { label: "Run mode", value: rec.run?.mode === "offline" ? "Offline heuristics" : rec.run?.mode === "manual" ? "Manual dry run" : "LLM agents" },
          ]} />
        </Panel>
        <Panel title="Result by workspace">
          <ul className="space-y-2">
            {d.results.map((r) => (
              <li key={r.workspace_id} className="flex items-center justify-between gap-2">
                <span className="truncate text-[14px]">{d.workspaces[r.workspace_id]?.name ?? r.workspace_id}</span>
                <ResultPill status={r.status} />
              </li>
            ))}
            {!d.results.length && <p className="text-fg-muted">No workspaces in scope.</p>}
          </ul>
        </Panel>
        {(rec.applicability?.length ?? 0) > 0 && (
          <Panel title="Applicability">
            <ul className="space-y-2 text-body-sm">
              {rec.applicability!.map((a) => (
                <li key={a.workspace_id}><span className="font-semibold">{d.workspaces[a.workspace_id]?.name ?? a.workspace_id}:</span> {a.status === "exposed" ? "Exposed" : a.status === "not_exposed" ? "Not exposed" : "Unknown"} <span className="text-fg-muted">— {a.reason}</span></li>
              ))}
            </ul>
          </Panel>
        )}
        {d.related.length > 0 && (
          <Panel title="Related research">
            <ul className="space-y-1">
              {d.related.map((r) => (
                <li key={r.id}>
                  <Link href={wsHref(`/research/${r.id}`)} className="block rounded-sm px-1 py-1.5 hover:bg-subtle">
                    <span className="block truncate text-[14px]">{r.title}</span>
                    <span className="font-mono text-mono-sm text-fg-muted">{r.id}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </Panel>
        )}
      </aside>

      <EditSummaryDialog open={editing === "summary"} onClose={() => setEditing(null)} value={rec.executive_summary}
        onSave={async (v) => { await patchRecord({ executive_summary: v }, "Edited executive summary"); setEditing(null); }} />
      <EditImpactDialog open={editing === "impact"} onClose={() => setEditing(null)} rec={rec}
        onSave={async (impact, severity) => { await patchRecord({ impact, severity }, "Edited impact"); setEditing(null); }} />
      <EditRecsDialog open={editing === "recs"} onClose={() => setEditing(null)} recs={rec.recommendations} patchingInsufficient={rec.patching_insufficient}
        onSave={async (recommendations, patching_insufficient) => { await patchRecord({ recommendations, patching_insufficient }, "Edited recommendations"); setEditing(null); }} />
    </div>
  );
}

function MitreTable({ rows, sources, canEdit, onRemove }: { rows: MitreRow[]; sources: Record<string, ResearchRecord["sources"][number]>; canEdit: boolean; onRemove: (tid: string) => void }) {
  if (!rows.length) return <p className="text-fg-muted">No techniques mapped.</p>;
  return (
    <div className="overflow-x-auto rounded-md border border-line">
      <table className="tl-table tl-compact w-full">
        <thead><tr><th>Tactic</th><th>Technique</th><th>Procedure</th><th>Evidence</th><th>Confidence</th><th>Sources</th>{canEdit && <th className="w-8"><span className="sr-only">Actions</span></th>}</tr></thead>
        <tbody>
          {rows.map((m) => (
            <tr key={m.technique_id + m.tactic_id}>
              <td className="whitespace-nowrap">{m.tactic}</td>
              <td className="min-w-[200px]"><AttackChip id={m.technique_id} name={m.sub_technique || m.technique} tactic={m.tactic} /></td>
              <td className="min-w-[220px]">{m.procedure}</td>
              <td className="min-w-[200px]">{m.evidence_quote ? <Quote>{m.evidence_quote}</Quote> : <span className="text-fg-faint">—</span>}</td>
              <td>{m.confidence.charAt(0).toUpperCase() + m.confidence.slice(1)}</td>
              <td><SourceRefs ids={m.source_ids} sources={sources} /></td>
              {canEdit && <td><button onClick={() => onRemove(m.technique_id)} aria-label={`Remove ${m.technique_id}`} className="grid size-7 place-items-center rounded-sm text-fg-muted hover:bg-danger-soft hover:text-danger"><Trash2 className="size-4" /></button></td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ResultsTable({ d, ws, reload, canEdit }: { d: DetailProps["d"]; ws: string; reload: () => Promise<void>; canEdit: boolean }) {
  const { workspaces } = useApp();
  const [editing, setEditing] = useState<string | null>(null);
  const rows = ws !== "all" ? d.results.filter((r) => r.workspace_id === ws) : d.results;
  return (
    <>
      {ws !== "all" && !rows.length && (
        <p className="mb-3 text-fg-muted">{workspaces.find((w) => w.id === ws)?.name} is not in scope for this research. {canEdit && <button className="prose-link" onClick={() => setEditing(ws)}>Record a result</button>}</p>
      )}
      <div className="space-y-3">
        {rows.map((r) => (
          <div key={r.workspace_id} className="rounded-md border border-line bg-surface p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-h4 font-semibold">{d.workspaces[r.workspace_id]?.name ?? r.workspace_id}</span>
              <ResultPill status={r.status} suffix={r.hunt_window ? `hunted ${r.hunt_window}` : undefined} />
              {canEdit && <Button size="sm" variant="tertiary" icon={<Pencil />} className="ml-auto" onClick={() => setEditing(r.workspace_id)}>Record result</Button>}
            </div>
            {r.summary && <p className="mt-2 text-[14px]">{r.summary}</p>}
            <p className="mt-1 text-caption text-fg-muted">
              {r.queries_run?.length ? `Queries run: ${r.queries_run.join(", ")} · ` : ""}{r.analyst ? `${r.analyst.name} · ` : ""}{utc(r.updated_at)}
            </p>
          </div>
        ))}
      </div>
      {editing && <ResultDialog d={d} wsId={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function ResultDialog({ d, wsId, onClose, onSaved }: { d: DetailProps["d"]; wsId: string; onClose: () => void; onSaved: () => void }) {
  const { wsName } = useApp();
  const cur = d.results.find((r) => r.workspace_id === wsId);
  const [status, setStatus] = useState<ResultStatus>(cur?.status ?? "pending");
  const [summary, setSummary] = useState(cur?.summary ?? "");
  const [windowTxt, setWindowTxt] = useState(cur?.hunt_window ?? "");
  const [qs, setQs] = useState<string[]>(cur?.queries_run ?? []);
  const [saving, setSaving] = useState(false);
  const toast = useToast();
  const opps = d.record.detection_opportunities;
  const save = async () => {
    setSaving(true);
    try {
      await put(`/api/research/${d.id}/results/${wsId}`, { status, summary, hunt_window: windowTxt, queries_run: qs });
      toast({ tone: "success", message: `Hunt result saved for ${wsName(wsId)}` });
      onSaved();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setSaving(false); }
  };
  return (
    <Dialog open onClose={onClose} title={`Hunt result · ${wsName(wsId)}`} size="md"
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={saving} onClick={save}>Save result</Button></>}>
      <div className="space-y-5">
        <Field label="Result" htmlFor="res-status">
          <Select id="res-status" value={status} onChange={(v) => setStatus(v as ResultStatus)} options={[
            { value: "no_evidence", label: "No evidence" }, { value: "suspicious", label: "Suspicious" }, { value: "confirmed", label: "Confirmed compromise" },
            { value: "not_applicable", label: "Not applicable" }, { value: "pending", label: "Pending" }]} />
        </Field>
        <Field label="Summary" htmlFor="res-sum" help="One or two sentences for the client report.">
          <Textarea id="res-sum" value={summary} onChange={(e) => setSummary(e.target.value)} className="min-h-[90px]" />
        </Field>
        <Field label="Hunt window" optional htmlFor="res-win"><Input id="res-win" value={windowTxt} onChange={(e) => setWindowTxt(e.target.value)} placeholder="e.g. 2025-07-01 – 2026-09-24" /></Field>
        {opps.length > 0 && (
          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Queries run</legend>
            <div className="space-y-1.5">{opps.map((o) => (
              <Checkbox key={o.id} checked={qs.includes(o.id)} onChange={(v) => setQs(v ? [...qs, o.id] : qs.filter((x) => x !== o.id))} label={<span><span className="font-mono text-mono-sm">{o.id}</span> {o.title}</span>} />
            ))}</div>
          </fieldset>
        )}
      </div>
    </Dialog>
  );
}

function EditSummaryDialog({ open, onClose, value, onSave }: { open: boolean; onClose: () => void; value: string; onSave: (v: string) => Promise<void> }) {
  const [v, setV] = useState(value);
  const [saving, setSaving] = useState(false);
  useEffect(() => setV(value), [value, open]);
  const words = v.trim().split(/\s+/).filter(Boolean).length;
  return (
    <Dialog open={open} onClose={onClose} title="Edit executive summary" size="lg"
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={saving} onClick={async () => { setSaving(true); try { await onSave(v); } finally { setSaving(false); } }}>Save summary</Button></>}>
      <Textarea value={v} onChange={(e) => setV(e.target.value)} className="min-h-[320px] text-body-lg" aria-label="Executive summary" data-autofocus />
      <p className={clsx("mt-1 text-caption", words < 150 || words > 250 ? "text-[var(--warning)]" : "text-fg-muted")}>{words} words · aim for 150–250, plain language, no IoCs</p>
    </Dialog>
  );
}

function EditImpactDialog({ open, onClose, rec, onSave }: { open: boolean; onClose: () => void; rec: ResearchRecord; onSave: (impact: ResearchRecord["impact"], sev: Severity) => Promise<void> }) {
  const [impact, setImpact] = useState(rec.impact);
  const [saving, setSaving] = useState(false);
  useEffect(() => setImpact(rec.impact), [rec.impact, open]);
  return (
    <Dialog open={open} onClose={onClose} title="Edit impact" size="md"
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={saving} onClick={async () => { setSaving(true); try { await onSave(impact, impact.severity); } finally { setSaving(false); } }}>Save impact</Button></>}>
      <div className="space-y-5">
        <Field label="Severity" htmlFor="imp-sev"><Select id="imp-sev" value={impact.severity} onChange={(v) => setImpact({ ...impact, severity: v as Severity })} options={SEVERITIES.map((s) => ({ value: s, label: SEVERITY[s].label }))} /></Field>
        <Field label="Business impact" htmlFor="imp-bi"><Textarea id="imp-bi" value={impact.business_impact} onChange={(e) => setImpact({ ...impact, business_impact: e.target.value })} className="min-h-[100px]" /></Field>
        <Field label="Blast radius" htmlFor="imp-br"><Textarea id="imp-br" value={impact.blast_radius} onChange={(e) => setImpact({ ...impact, blast_radius: e.target.value })} className="min-h-[70px]" /></Field>
        <fieldset className="flex flex-wrap gap-5">
          <legend className="mb-1.5 text-[13px] font-semibold">Affects</legend>
          {(["confidentiality", "integrity", "availability"] as const).map((k) => (
            <Checkbox key={k} checked={impact.cia[k]} onChange={(v) => setImpact({ ...impact, cia: { ...impact.cia, [k]: v } })} label={k.charAt(0).toUpperCase() + k.slice(1)} />
          ))}
        </fieldset>
      </div>
    </Dialog>
  );
}

function EditRecsDialog({ open, onClose, recs, patchingInsufficient, onSave }:
  { open: boolean; onClose: () => void; recs: ResearchRecord["recommendations"]; patchingInsufficient: boolean; onSave: (r: ResearchRecord["recommendations"], p: boolean) => Promise<void> }) {
  const [items, setItems] = useState(recs);
  const [pi, setPi] = useState(patchingInsufficient);
  const [saving, setSaving] = useState(false);
  useEffect(() => { setItems(recs); setPi(patchingInsufficient); }, [recs, patchingInsufficient, open]);
  const upd = (i: number, p: Partial<ResearchRecord["recommendations"][number]>) => setItems(items.map((x, j) => (j === i ? { ...x, ...p } : x)));
  return (
    <Dialog open={open} onClose={onClose} title="Edit recommendations" size="lg"
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={saving} onClick={async () => { setSaving(true); try { await onSave(items.filter((x) => x.action.trim()), pi); } finally { setSaving(false); } }}>Save recommendations</Button></>}>
      <div className="space-y-3">
        <Checkbox checked={pi} onChange={setPi} label="Patching alone is insufficient" />
        {items.map((r, i) => (
          <div key={i} className="grid gap-2 rounded-md border border-line p-3 sm:grid-cols-[150px_1fr_160px_auto]">
            <Select value={r.horizon} onChange={(v) => upd(i, { horizon: v as typeof r.horizon })} ariaLabel="Horizon" options={[{ value: "immediate", label: "Immediate" }, { value: "short_term", label: "Short term" }, { value: "strategic", label: "Strategic" }]} />
            <Textarea value={r.action} onChange={(e) => upd(i, { action: e.target.value })} className="!min-h-[36px]" aria-label="Action" rows={2} />
            <Input value={r.owner_role} onChange={(e) => upd(i, { owner_role: e.target.value })} aria-label="Owner role" placeholder="Owner role" />
            <button onClick={() => setItems(items.filter((_, j) => j !== i))} aria-label="Remove recommendation" className="grid size-9 place-items-center rounded-sm text-fg-muted hover:bg-danger-soft hover:text-danger"><Trash2 className="size-4" /></button>
          </div>
        ))}
        <Button icon={<Plus />} onClick={() => setItems([...items, { horizon: "short_term", action: "", owner_role: "", source_ids: [] }])}>Add recommendation</Button>
        <p className="text-caption text-fg-muted">New recommendations without a source are marked unsupported until you cite one.</p>
      </div>
    </Dialog>
  );
}
