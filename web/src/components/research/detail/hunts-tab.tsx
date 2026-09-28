"use client";

import { Code, Download, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { download, get, patch, post } from "@/lib/api";
import { PROVENANCE, QUERY_TYPE } from "@/lib/constants";
import type { Query } from "@/lib/types";
import { useApp } from "../../providers";
import { Badge, CountBadge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { Alert, EmptyState, useToast } from "../../ui/feedback";
import { Segmented } from "../../ui/forms";
import { statusLabel, type MappedFields, type ResearchQueriesResponse } from "../hunts/query-lifecycle";
import { groupAnchor, groupQueries, sourceIndex } from "../provenance";
import { QueryBlock } from "../query-block";
import type { DetailProps } from "./common";

/** Spec §7.3: grouped by IoC / IoA / Vulnerability / TTP. One card per detection, platform variants as tabs. */
const GROUPS: { type: Query["type"]; label: string; help: string }[] = [
  { type: "ioc", label: "IoC detections", help: "Retro-hunt known-bad values." },
  { type: "ioa", label: "IoA detections", help: "Behaviour that survives indicator rotation." },
  { type: "vuln", label: "Vulnerability detections", help: "Find exposed or unpatched assets." },
  { type: "ttp", label: "TTP detections", help: "Wider technique hunts, not threat-specific." },
];
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export function HuntsTab({ d, reload, canEdit, ws }: DetailProps) {
  const { platformName, workspaces } = useApp();
  const toast = useToast();
  const rec = d.record;
  const all = useMemo(() => rec.hunts?.queries ?? [], [rec.hunts]);
  const workspace = workspaces.find((w) => w.id === ws) ?? null;
  const [type, setType] = useState<string>("all");
  const [prov, setProv] = useState<string>("all");
  const [busy, setBusy] = useState(false);
  const sources = useMemo(() => sourceIndex(rec), [rec]);
  const detections = useMemo(() => groupQueries(rec), [rec]);
  // Server-side field mapping for the active workspace (mapped_body / mapped_lint / mapping_applied per query).
  const [mapped, setMapped] = useState<{ key: string; byId: Record<string, MappedFields> } | null>(null);
  const mapKey = workspace ? `${d.id}|${workspace.id}|${d.version}|${d.updated_at}` : null;
  useEffect(() => {
    if (!mapKey || !workspace) return;
    let live = true;
    get<ResearchQueriesResponse>(`/api/research/${d.id}/queries?ws=${encodeURIComponent(workspace.id)}&include_reference=true`)
      .then((r) => { if (live) setMapped({ key: mapKey, byId: Object.fromEntries(r.items.map((q) => [q.id, { mapped_body: q.mapped_body, mapped_lint: q.mapped_lint, mapping_applied: q.mapping_applied }])) }); })
      .catch(() => { if (live) setMapped({ key: mapKey, byId: {} }); });
    return () => { live = false; };
  }, [mapKey, workspace, d.id]);
  const mappedById = mapped && mapped.key === mapKey ? mapped.byId : undefined;
  const provenances = useMemo(() => Array.from(new Set(detections.map((g) => g.provenance))), [detections]);

  const gapsFor = (oppId: string | null) =>
    (rec.coverage_gaps ?? []).filter((g) => (ws === "all" || g.workspace_id === ws) && g.opportunity_id === oppId).map((g) => g.detail);
  const missingPlatforms = workspace ? workspace.platforms.filter((p) => !rec.hunts.platforms.includes(p)) : [];

  const inProv = (p: string) => prov === "all" || p === prov;
  const grouped = useMemo(() => GROUPS.map((g) => {
    const blocks = detections.filter((x) => x.type === g.type && (prov === "all" || x.provenance === prov));
    return { ...g, count: blocks.length, variants: blocks.reduce((a, b) => a + b.queries.length, 0), blocks };
  }), [detections, prov]);
  const typeCount = (t: string) => detections.filter((x) => x.type === t && inProv(x.provenance)).length;
  const shown = grouped.filter((g) => type === "all" || type === g.type);
  const shownDet = shown.reduce((a, g) => a + g.count, 0), shownVar = shown.reduce((a, g) => a + g.variants, 0);

  /** Rejects on error (after toasting the API detail) so the query block can roll back its optimistic status. */
  const onPatch = async (qid: string, body: { status?: string; body?: string }) => {
    try {
      await patch(`/api/research/${d.id}/queries/${qid}`, body);
    } catch (e) {
      toast({ tone: "danger", message: (e as Error).message });
      throw e;
    }
    toast({ tone: "success", message: body.body ? "Query saved" : body.status === "generated" ? "Issue reported; query moved back to Generated" : `Query marked ${statusLabel(body.status ?? "")}` });
    await reload();
  };

  const generate = async (platforms: string[]) => {
    setBusy(true);
    try {
      await post(`/api/research/${d.id}/rerun`, { from_stage: "queries", platforms: Array.from(new Set([...rec.hunts.platforms, ...platforms])) });
      toast({ tone: "info", message: `Generating ${platforms.map((p) => platformName(p, true)).join(", ")} queries…` });
      setTimeout(reload, 2500);
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(false); }
  };

  if (!all.length) {
    return <EmptyState icon={<Code />} title="No queries yet" body="Queries appear after the Query generation stage of the run." />;
  }
  return (
    <div className="min-w-0 space-y-8">
      {missingPlatforms.length > 0 && (
        <Alert tone="info" title={`No queries for ${workspace!.name}'s ${missingPlatforms.map((p) => platformName(p, true)).join(", ")}`}
          action={canEdit && <Button size="sm" icon={<RefreshCw />} loading={busy} onClick={() => generate(missingPlatforms)}>Generate {missingPlatforms.map((p) => platformName(p, true)).join(", ")} queries</Button>}>
          This run generated {rec.hunts.platforms.map((p) => platformName(p, true)).join(", ")} only. Re-running query generation reuses the existing sources and analysis.
        </Alert>
      )}
      <div className="space-y-3">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-2">
          <p className="text-h3 font-semibold">{plural(detections.length, "detection", "detections")} <span className="font-normal text-fg-muted">· {plural(all.length, "platform variant", "platform variants")}</span></p>
          <span className="text-caption text-fg-muted">Look-back {rec.hunts.lookback_days} days · {workspace ? `showing queries mapped for ${workspace.name}` : "select a workspace to apply its field mappings"}</span>
          <Button size="sm" className="ml-auto" icon={<Download />} onClick={() => download(`/api/research/${d.id}/export/queries_csv${ws !== "all" ? `?ws=${ws}` : ""}`)}>Queries CSV</Button>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="max-w-full overflow-x-auto">
            <Segmented ariaLabel="Detection type" value={type} onChange={setType} options={[
              { value: "all", label: <>All <CountBadge>{GROUPS.reduce((a, g) => a + typeCount(g.type), 0)}</CountBadge></> },
              ...GROUPS.filter((g) => detections.some((x) => x.type === g.type)).map((g) => ({ value: g.type, label: <>{QUERY_TYPE[g.type]} <CountBadge>{typeCount(g.type)}</CountBadge></> })),
            ]} />
          </div>
          {provenances.length > 1 && (
            <div className="max-w-full overflow-x-auto">
              <Segmented ariaLabel="Where the detection came from" value={prov} onChange={setProv} options={[
                { value: "all", label: "Any origin" },
                ...(["vendor", "derived", "generic"] as const).filter((p) => provenances.includes(p)).map((p) => ({ value: p, label: PROVENANCE[p].short })),
              ]} />
            </div>
          )}
          {(type !== "all" || prov !== "all") && <span className="text-caption text-fg-muted">Showing {plural(shownDet, "detection", "detections")} · {plural(shownVar, "variant", "variants")}</span>}
        </div>
      </div>

      {shown.filter((g) => g.count).map((g) => (
        <section key={g.type} className="min-w-0">
          <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h2 className="text-h2 font-semibold">{g.label}</h2>
            <span className="text-body-sm text-fg-muted">{plural(g.count, "detection", "detections")} · {plural(g.variants, "variant", "variants")} — {g.help}</span>
          </div>
          <div className="space-y-4">
            {g.blocks.map((b) => (
              <QueryBlock key={b.key} id={groupAnchor(b.key)} title={b.title} refId={b.opportunityId ?? b.queries[0].group ?? null} queries={b.queries} workspace={workspace} mapped={mappedById}
                gaps={gapsFor(b.opportunityId)} onPatch={canEdit ? onPatch : undefined} canEdit={canEdit}
                provenance={b.provenance} sourceIds={b.sourceIds} sources={sources} />
            ))}
          </div>
        </section>
      ))}
      {!shownDet && <p className="text-fg-muted">No detections match these filters.</p>}

      {rec.log_sources_required.length > 0 && (
        <section className="min-w-0">
          <h2 className="mb-3 text-h2 font-semibold">Required log sources</h2>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="tl-table tl-compact w-full">
              <thead><tr><th>Data source</th><th>Windows / Sysmon</th>{rec.hunts.platforms.filter((p) => p !== "sigma").map((p) => <th key={p}>{platformName(p, true)}</th>)}</tr></thead>
              <tbody>
                {rec.log_sources_required.map((l) => (
                  <tr key={l.data_source}>
                    <td className="font-semibold">{l.label}{workspace && !workspace.log_sources.includes(l.data_source) && <Badge tone="warning" className="ml-2">Gap</Badge>}</td>
                    <td>{l.windows ?? "—"}</td>
                    {rec.hunts.platforms.filter((p) => p !== "sigma").map((p) => <td key={p} className={l[p]?.startsWith("—") ? "text-fg-muted" : ""}>{l[p] ?? "—"}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
