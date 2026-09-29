"use client";

import clsx from "clsx";
import { ArrowLeftRight, CircleAlert, Ellipsis, ExternalLink, FileCode, Pencil, TriangleAlert, Flag } from "lucide-react";
import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { DATA_SOURCES, QUERY_TYPE } from "@/lib/constants";
import type { Provenance, Query, Source, Workspace } from "@/lib/types";
import { useApp, useWsHref } from "../providers";
import { AttackChip, Badge, Chip } from "../ui/badges";
import { Button, CopyButton } from "../ui/button";
import { Segmented, Textarea } from "../ui/forms";
import { PillTabs } from "../ui/layout";
import { Menu } from "../ui/overlay";
import { ProvenanceBadge, SourceChips } from "./provenance";
import { StatusPicker, useOptimisticStatus, type MappedFields } from "./hunts/query-lifecycle";
import { highlight } from "./syntax";

export function CodeView({ body, platform, maxLines = 18 }: { body: string; platform: string; maxLines?: number }) {
  const [all, setAll] = useState(false);
  const lines = body.split("\n");
  const shown = all ? lines : lines.slice(0, maxLines);
  return (
    <div className="bg-code">
      <div className={clsx("overflow-auto py-2", !all && "max-h-[360px]")}>
        <table className="w-max min-w-full border-collapse font-mono text-mono">
          <tbody>
            {shown.map((l, i) => (
              <tr key={i}>
                <td className="w-10 select-none pr-3 text-right align-top text-fg-faint" aria-hidden>{i + 1}</td>
                <td className="pr-4 whitespace-pre text-fg">{highlight(l, platform)}{l === "" ? " " : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {lines.length > maxLines && (
        <button onClick={() => setAll(!all)} className="w-full border-t border-line py-1.5 text-[13px] font-semibold text-accent-text hover:bg-subtle">
          {all ? "Show fewer lines" : `Show all ${lines.length} lines`}
        </button>
      )}
    </div>
  );
}

/** Query block (design.md 18.3): one detection opportunity, tabs per selected platform. */
export function QueryBlock({ title, refId, queries, workspace, mapped, gaps, onPatch, canEdit = true, defaultPlatform, provenance, sourceIds, sources, id }:
  { title: string; refId?: string | null; queries: Query[]; workspace?: Workspace | null;
    /** Server-side field mapping per query id (GET /api/research/{id}/queries?ws=). `undefined` = not requested / loading. */
    mapped?: Record<string, MappedFields>; gaps?: string[];
    onPatch?: (qid: string, patch: { status?: string; body?: string }) => Promise<void>; canEdit?: boolean; defaultPlatform?: string;
    /** Source trail: shown under the title when given. */
    provenance?: Provenance; sourceIds?: string[]; sources?: Record<string, Source>; id?: string }) {
  const { platformName, ws } = useApp();
  const wsHref = useWsHref();
  const sorted = useMemo(() => [...queries].sort((a, b) => (a.platform === "sigma" ? 1 : 0) - (b.platform === "sigma" ? 1 : 0)), [queries]);
  const preferred = sorted.find((q) => q.platform === defaultPlatform) ?? sorted.find((q) => workspace?.platforms?.includes(q.platform)) ?? sorted[0];
  const [pid, setPid] = useState(preferred?.id);
  const q = sorted.find((x) => x.id === pid) ?? sorted[0];
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [view, setView] = useState<"mapped" | "raw">("mapped");
  const commitStatus = useCallback((s: string) => onPatch ? onPatch(q?.id ?? "", { status: s }) : Promise.resolve(), [onPatch, q?.id]);
  const st = useOptimisticStatus(q?.status ?? "", commitStatus);
  if (!q) return null;
  const m = workspace ? mapped?.[q.id] : undefined;
  const hasMapped = typeof m?.mapped_body === "string";
  const showMapped = hasMapped && !!m?.mapping_applied && view === "mapped";
  const body = showMapped ? m!.mapped_body! : q.body;
  const lint = showMapped ? (m!.mapped_lint ?? []) : (q.lint ?? []);
  const gapHere = (gaps ?? []).length > 0;
  const sigma = sorted.find((x) => x.platform === "sigma");

  return (
    <section id={id} className="min-w-0 scroll-mt-32 overflow-hidden rounded-md border border-line bg-surface" aria-label={title}>
      <header className="flex flex-wrap items-start gap-x-3 gap-y-2 border-b border-line px-4 pt-3 pb-2">
        <div className="min-w-0 flex-1">
          <h4 className="text-h4 font-semibold break-words [overflow-wrap:anywhere]">
            {refId && <span className="font-mono text-mono-sm text-fg-muted">{refId} · </span>}{title}
          </h4>
          {(provenance || sources) && (
            <div className="mt-1.5 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              {provenance && <ProvenanceBadge provenance={provenance} />}
              {sources && <SourceChips ids={sourceIds ?? []} sources={sources} empty={provenance === "generic" ? "Not tied to a specific source" : "No source recorded"} />}
            </div>
          )}
        </div>
        <Badge>{QUERY_TYPE[q.type] ?? q.type}</Badge>
        <StatusPicker status={st.status} origin={q.origin} lint={q.lint} busy={st.busy} onChange={canEdit && onPatch ? st.change : undefined} />
      </header>
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2 px-4 py-2">
        <PillTabs ariaLabel="Platform" value={q.id} onChange={(id) => { setPid(id); setEditing(false); }}
          tabs={sorted.map((x) => ({ id: x.id, label: platformName(x.platform, true) }))} />
        <div className="flex items-center gap-1">
          {!editing && <CopyButton text={body} label={showMapped ? "Copy mapped" : "Copy query"} copiedLabel="Copied" />}
          <Menu width={210} items={[
            { label: "Open in library", icon: <ExternalLink />, onSelect: () => { window.location.href = wsHref(`/library/queries/${q.id}`); } },
            ...(canEdit && onPatch ? [
              { label: "Edit", icon: <Pencil />, onSelect: () => { setDraft(q.body); setEditing(true); } },
            ] : []),
            ...(sigma && q.platform !== "sigma" ? [{ label: "View Sigma", icon: <FileCode />, onSelect: () => setPid(sigma.id) }] : []),
            ...(canEdit && onPatch && q.origin !== "reference" && st.status !== "generated" ? [{ label: "Report issue", icon: <Flag />, onSelect: () => st.change("generated") }] : []),
          ]} trigger={(p) => (
            <button {...p} aria-label="More query actions" className="grid size-7 place-items-center rounded-sm text-fg-muted hover:bg-subtle"><Ellipsis className="size-4" /></button>
          )} />
        </div>
      </div>
      {!editing && workspace && (hasMapped ? (
        <div className="flex min-w-0 flex-wrap items-center gap-2 px-4 pb-2">
          {m!.mapping_applied ? <>
            <Badge tone="accent" title={`${workspace.name} field mappings for ${platformName(q.platform, true)} applied by the server`}>
              <ArrowLeftRight className="mr-1 inline size-3.5 align-[-2px]" aria-hidden />Mapped for {workspace.name}
            </Badge>
            <Segmented size="sm" ariaLabel="Query text" value={view} onChange={setView} options={[{ value: "mapped", label: "Mapped" }, { value: "raw", label: "Raw" }]} />
            {view === "raw" && <span className="text-caption text-fg-muted">Showing the query as generated</span>}
          </> : <span className="text-caption text-fg-muted">No {workspace.name} field mappings for {platformName(q.platform, true)}; query shown as generated.</span>}
        </div>
      ) : mapped === undefined ? <p className="px-4 pb-2 text-caption text-fg-muted">Loading {workspace.name} field mappings…</p> : null)}
      {!editing && !workspace && ws === "all" && (
        <p className="px-4 pb-2 text-caption text-fg-muted">Raw query · pick a workspace to apply its field mappings.</p>
      )}
      {editing ? (
        <div className="space-y-2 border-t border-line p-3">
          <Textarea value={draft} onChange={(e) => setDraft(e.target.value)} className="min-h-[200px] font-mono text-mono" spellCheck={false} aria-label="Query text" />
          <div className="flex justify-end gap-2">
            <Button size="sm" onClick={() => setEditing(false)}>Cancel</Button>
            <Button size="sm" variant="primary" loading={saving} onClick={async () => { setSaving(true); try { await onPatch!(q.id, { body: draft }); setEditing(false); } catch { /* onPatch reports */ } finally { setSaving(false); } }}>Save query</Button>
          </div>
        </div>
      ) : (
        <div className="border-t border-line"><CodeView body={body} platform={q.platform} /></div>
      )}
      <footer className="space-y-2 border-t border-line px-4 py-3">
        {lint.length > 0 && (
          <p className="flex items-start gap-1.5 text-body-sm text-danger"><CircleAlert className="mt-0.5 size-4 shrink-0" />{showMapped ? `Lint (mapped for ${workspace!.name})` : "Lint"}: {lint.join("; ")}</p>
        )}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          {q.log_sources?.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-caption text-fg-muted">Requires</span>
              {q.log_sources.map((l) => <Chip key={l}>{l}</Chip>)}
            </div>
          )}
          {gapHere && (
            <span className="inline-flex items-center gap-1.5 text-body-sm font-semibold" style={{ color: "var(--warning)" }}>
              <TriangleAlert className="size-4" />Coverage gap: {gaps!.join("; ")}
            </span>
          )}
          <div className="ml-auto flex flex-wrap gap-1.5">
            {q.techniques?.map((t) => <AttackChip key={t} id={t} />)}
          </div>
        </div>
        {q.fp_notes && <p className="text-body-sm text-fg-strong"><span className="text-fg-muted">False positives: </span>{q.fp_notes}</p>}
        {q.data_sources?.length > 0 && <p className="text-caption text-fg-muted">Data source: {q.data_sources.map((d) => DATA_SOURCES[d] ?? d).join(", ")} · <Link className="hover:underline" href={wsHref(`/library/queries/${q.id}`)}><span className="font-mono">{q.id}</span></Link></p>}
      </footer>
    </section>
  );
}
