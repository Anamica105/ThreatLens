"use client";

import { ArrowLeftRight, CircleAlert, Pencil } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { SeenIn } from "@/components/library";
import { useApp, useWsHref } from "@/components/providers";
import { allowedStatuses, statusLabel, type MappedFields } from "@/components/research/hunts/query-lifecycle";
import { CodeView } from "@/components/research/query-block";
import { ProvenanceBadge, SourceTrail } from "@/components/research/provenance";
import { AttackChip, Badge, Chip, QueryStatusPill } from "@/components/ui/badges";
import { Button, CopyButton } from "@/components/ui/button";
import { ErrorState, Skeleton, useToast } from "@/components/ui/feedback";
import { Field, MultiSelect, Segmented, Select, Textarea } from "@/components/ui/forms";
import { DefinitionList, Page, PageHeader, Panel } from "@/components/ui/layout";
import { patch } from "@/lib/api";
import { QUERY_TYPE } from "@/lib/constants";
import { utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Provenance, ProvenanceItem, ResearchStatus, Severity } from "@/lib/types";

interface QD extends MappedFields {
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
  // With a workspace active the API adds mapped_body / mapped_lint / mapping_applied (server-side field mapping).
  const { data: q, error, reload, setData } = useApi<QD>(`/api/library/queries/${id}${activeWorkspace ? `?ws=${encodeURIComponent(activeWorkspace.id)}` : ""}`);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [view, setView] = useState<"mapped" | "raw">("mapped");
  const [pendingStatus, setPendingStatus] = useState<string | null>(null);
  if (error) return <Page><ErrorState error={error} onRetry={reload} /></Page>;
  if (!q) return <Page><div className="space-y-3 pt-8"><Skeleton className="h-8 w-1/3" /><Skeleton className="h-60 w-full" /></div></Page>;
  const save = async (body: Record<string, unknown>, msg: string) => {
    try {
      await patch<QD>(`/api/library/queries/${q.id}`, body);
      // The PATCH response has no workspace mapping; refetch so mapped_body follows the saved text.
      await reload();
      toast({ tone: "success", message: msg });
      return true;
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); return false; }
  };
  /** Optimistic status change; the server value comes back on failure (409 lint / 422 unknown, detail in the toast). */
  const changeStatus = async (v: string) => {
    const prev = q;
    setPendingStatus(v);
    setData({ ...q, status: v });
    const ok = await save({ status: v }, `Marked ${statusLabel(v)}`);
    if (!ok) setData(prev);
    setPendingStatus(null);
  };
  const hasMapped = !!activeWorkspace && typeof q.mapped_body === "string";
  const showMapped = hasMapped && !!q.mapping_applied && view === "mapped";
  const shown = showMapped ? q.mapped_body! : q.body;
  const statusOptions = [q.status, ...allowedStatuses(q.status, q.origin, undefined)];
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "Queries", href: "/library/queries" }, { label: q.id, mono: true }]} title={<span className="break-words [overflow-wrap:anywhere]">{q.title}</span>}
        description={<span className="flex flex-wrap items-center gap-2"><Badge>{platformName(q.platform)}</Badge><Badge>{QUERY_TYPE[q.type] ?? q.type}</Badge>{q.provenance_kind && <ProvenanceBadge provenance={q.provenance_kind} />}<QueryStatusPill status={q.status} /><span>v{q.version}</span>{q.group && <span className="font-mono text-mono-sm">{q.group}</span>}</span>}
        actions={<>
          {!editing && <Button icon={<Pencil />} onClick={() => { setDraft(q.body); setEditing(true); }}>Edit query</Button>}
          <CopyButton text={shown} label={showMapped ? "Copy mapped" : "Copy query"} size="md" variant="primary" />
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
            {!editing && (hasMapped ? (
              <div className="flex min-w-0 flex-wrap items-center gap-2 border-b border-line px-4 py-2">
                {q.mapping_applied ? <>
                  <Badge tone="accent"><ArrowLeftRight className="mr-1 inline size-3.5 align-[-2px]" aria-hidden />Mapped for {activeWorkspace!.name}</Badge>
                  <Segmented size="sm" ariaLabel="Query text" value={view} onChange={setView} options={[{ value: "mapped", label: "Mapped" }, { value: "raw", label: "Raw" }]} />
                  {view === "raw" && <span className="text-caption text-fg-muted">Showing the query as generated</span>}
                </> : <span className="text-caption text-fg-muted">No {activeWorkspace!.name} field mappings for {platformName(q.platform, true)}; query shown as generated.</span>}
              </div>
            ) : !activeWorkspace ? (
              <p className="border-b border-line px-4 py-2 text-caption text-fg-muted">Raw query · pick a workspace to apply its field mappings.</p>
            ) : null)}
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
              {showMapped && (q.mapped_lint?.length ?? 0) > 0 && (
                <p className="flex items-start gap-1.5 text-body-sm text-danger"><CircleAlert className="mt-0.5 size-4 shrink-0" />Lint (mapped for {activeWorkspace!.name}): {q.mapped_lint!.join("; ")}</p>
              )}
            </div>
          </section>
          <SourceTrail items={q.provenance} total={q.provenance_total} wsHref={wsHref} />
          <SeenIn items={q.seen_in} />
        </div>
        <aside className="min-w-0 space-y-4">
          <Panel title="Lifecycle">
            <div className="space-y-4">
              <Field label="Status" htmlFor="q-status" help="Generated → Syntax-checked → Reviewed → Lab-tested → Deployed">
                <Select id="q-status" value={q.status} onChange={changeStatus} disabled={pendingStatus !== null}
                  options={statusOptions.map((k) => ({ value: k, label: statusLabel(k) }))} />
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
