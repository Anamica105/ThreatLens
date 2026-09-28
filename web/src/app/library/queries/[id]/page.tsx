"use client";

import { Pencil } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { SeenIn } from "@/components/library";
import { useApp, useWsHref } from "@/components/providers";
import { applyMappings, CodeView } from "@/components/research/query-block";
import { ProvenanceBadge, SourceTrail } from "@/components/research/provenance";
import { AttackChip, Badge, Chip, QueryStatusPill } from "@/components/ui/badges";
import { Button, CopyButton } from "@/components/ui/button";
import { ErrorState, Skeleton, useToast } from "@/components/ui/feedback";
import { Field, MultiSelect, Select, Textarea } from "@/components/ui/forms";
import { DefinitionList, Page, PageHeader, Panel } from "@/components/ui/layout";
import { patch } from "@/lib/api";
import { QUERY_STATUS, QUERY_TYPE } from "@/lib/constants";
import { utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Provenance, ProvenanceItem, ResearchStatus, Severity } from "@/lib/types";

interface QD {
  id: string; title: string; platform: string; type: string; body: string; log_sources: string[]; techniques: string[]; fp_notes: string;
  status: string; version: number; origin: string; sigma_ref: string | null; deployed_workspaces: string[]; last_hit: string | null; updated_at: string;
  research_count: number; siblings: { id: string; platform: string; status: string }[];
  seen_in: { id: string; title: string; severity: Severity; status: ResearchStatus; created_at: string }[];
  provenance?: ProvenanceItem[]; provenance_total?: number; provenance_kind?: Provenance; group?: string | null;
}

export default function QueryDetail() {
  const { id } = useParams<{ id: string }>();
  const { platformName, workspaces, activeWorkspace } = useApp();
  const wsHref = useWsHref();
  const toast = useToast();
  const { data: q, error, reload, setData } = useApi<QD>(`/api/library/queries/${id}`);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  if (error) return <Page><ErrorState error={error} onRetry={reload} /></Page>;
  if (!q) return <Page><div className="space-y-3 pt-8"><Skeleton className="h-8 w-1/3" /><Skeleton className="h-60 w-full" /></div></Page>;
  const save = async (body: Record<string, unknown>, msg: string) => {
    try {
      const r = await patch<QD>(`/api/library/queries/${q.id}`, body);
      setData(r);
      toast({ tone: "success", message: msg });
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
  };
  const shown = applyMappings(q.body, q.platform, activeWorkspace);
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "Queries", href: "/library/queries" }, { label: q.id, mono: true }]} title={<span className="break-words [overflow-wrap:anywhere]">{q.title}</span>}
        description={<span className="flex flex-wrap items-center gap-2"><Badge>{platformName(q.platform)}</Badge><Badge>{QUERY_TYPE[q.type] ?? q.type}</Badge>{q.provenance_kind && <ProvenanceBadge provenance={q.provenance_kind} />}<QueryStatusPill status={q.status} /><span>v{q.version}</span>{q.group && <span className="font-mono text-mono-sm">{q.group}</span>}</span>}
        actions={<>
          {!editing && <Button icon={<Pencil />} onClick={() => { setDraft(q.body); setEditing(true); }}>Edit query</Button>}
          <CopyButton text={shown} label="Copy query" size="md" variant="primary" />
        </>} />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-6">
          <section className="min-w-0 overflow-hidden rounded-md border border-line bg-surface">
            {q.siblings.length > 0 && (
              <div className="flex flex-wrap items-center gap-1 border-b border-line px-4 py-2">
                <span className="mr-1 text-caption text-fg-muted">Same detection on</span>
                {q.siblings.map((s) => <Chip key={s.id} href={wsHref(`/library/queries/${s.id}`)}>{platformName(s.platform, true)}</Chip>)}
              </div>
            )}
            {editing ? (
              <div className="space-y-2 p-3">
                <Textarea value={draft} onChange={(e) => setDraft(e.target.value)} className="min-h-[280px] font-mono text-mono" spellCheck={false} aria-label="Query text" />
                <div className="flex justify-end gap-2">
                  <Button onClick={() => setEditing(false)}>Cancel</Button>
                  <Button variant="primary" onClick={async () => { await save({ body: draft }, "Query saved as a new version"); setEditing(false); }}>Save new version</Button>
                </div>
              </div>
            ) : <CodeView body={shown} platform={q.platform} maxLines={40} />}
            <div className="space-y-2 border-t border-line px-4 py-3">
              {q.log_sources.length > 0 && <div className="flex flex-wrap items-center gap-1.5"><span className="text-caption text-fg-muted">Requires</span>{q.log_sources.map((l) => <Chip key={l}>{l}</Chip>)}</div>}
              {q.fp_notes && <p className="text-body-sm break-words"><span className="text-fg-muted">False positives: </span>{q.fp_notes}</p>}
              {activeWorkspace && Object.keys(activeWorkspace.field_mappings?.[q.platform] ?? {}).length > 0 && <p className="text-caption text-fg-muted">{activeWorkspace.name} field mappings applied.</p>}
            </div>
          </section>
          <SourceTrail items={q.provenance} total={q.provenance_total} wsHref={wsHref} />
          <SeenIn items={q.seen_in} />
        </div>
        <aside className="min-w-0 space-y-4">
          <Panel title="Lifecycle">
            <div className="space-y-4">
              <Field label="Status" htmlFor="q-status" help="Generated → Syntax-checked → Reviewed → Lab-tested → Deployed">
                <Select id="q-status" value={q.status} onChange={(v) => save({ status: v }, `Marked ${QUERY_STATUS[v]?.label ?? v}`)}
                  options={Object.entries(QUERY_STATUS).filter(([k]) => k !== "reference" || q.origin === "reference").map(([k, v]) => ({ value: k, label: v.label }))} />
              </Field>
              <Field label="Deployed to" htmlFor="q-dep">
                <MultiSelect id="q-dep" ariaLabel="Deployed to" values={q.deployed_workspaces} onChange={(v) => save({ deployed_workspaces: v }, "Deployment updated")}
                  options={workspaces.map((w) => ({ value: w.id, label: w.name, color: w.color }))} placeholder="Not deployed" />
              </Field>
            </div>
          </Panel>
          <Panel title="Details">
            <DefinitionList items={[
              { label: "Query ID", value: <span className="font-mono">{q.id}</span> },
              { label: "Origin", value: q.origin === "reference" ? "Vendor reference" : "Generated" },
              { label: "Sigma source", value: q.sigma_ref ? <Link className="font-mono text-accent-text hover:underline" href={wsHref(`/library/queries/${q.sigma_ref}`)}>{q.sigma_ref}</Link> : q.platform === "sigma" ? "This rule" : "—" },
              { label: "Techniques", value: q.techniques.length ? <span className="flex flex-wrap gap-1">{q.techniques.map((t) => <AttackChip key={t} id={t} />)}</span> : "—" },
              { label: "Clients deployed", value: q.deployed_workspaces.length },
              { label: "Last hit", value: q.last_hit ? utc(q.last_hit) : "—" },
              { label: "Updated", value: utc(q.updated_at) },
            ]} />
          </Panel>
        </aside>
      </div>
    </Page>
  );
}
