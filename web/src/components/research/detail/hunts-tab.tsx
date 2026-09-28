"use client";

import { Code, Download, RefreshCw } from "lucide-react";
import { useMemo, useState } from "react";
import { download, patch, post } from "@/lib/api";
import { QUERY_TYPE } from "@/lib/constants";
import type { Query } from "@/lib/types";
import { useApp } from "../../providers";
import { Badge, CountBadge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { Alert, EmptyState, useToast } from "../../ui/feedback";
import { Segmented } from "../../ui/forms";
import { QueryBlock } from "../query-block";
import type { DetailProps } from "./common";

const GROUPS: { type: Query["type"] | "reference"; label: string; help: string }[] = [
  { type: "ioa", label: "IoA queries", help: "Behaviour that survives indicator rotation." },
  { type: "ioc", label: "IoC queries", help: "Retro-hunt known-bad values." },
  { type: "vuln", label: "Vulnerability queries", help: "Find exposed or unpatched assets." },
  { type: "ttp", label: "TTP queries", help: "Wider technique hunts, not threat-specific." },
  { type: "reference", label: "Vendor reference queries", help: "Queries published by the sources, stored verbatim." },
];

export function HuntsTab({ d, reload, canEdit, ws }: DetailProps) {
  const { platformName, workspaces } = useApp();
  const toast = useToast();
  const rec = d.record;
  const all = useMemo(() => rec.hunts?.queries ?? [], [rec.hunts]);
  const workspace = workspaces.find((w) => w.id === ws) ?? null;
  const [type, setType] = useState<string>("all");
  const [busy, setBusy] = useState(false);

  const gapsFor = (oppId: string | null) =>
    (rec.coverage_gaps ?? []).filter((g) => (ws === "all" || g.workspace_id === ws) && g.opportunity_id === oppId).map((g) => g.detail);
  const missingPlatforms = workspace ? workspace.platforms.filter((p) => !rec.hunts.platforms.includes(p)) : [];

  const grouped = useMemo(() => GROUPS.map((g) => {
    const qs = all.filter((q) => (g.type === "reference" ? q.origin === "reference" : q.type === g.type && q.origin !== "reference"));
    const blocks = new Map<string, Query[]>();
    for (const q of qs) {
      const key = q.opportunity_id ?? (g.type === "reference" ? q.id : q.title);
      blocks.set(key, [...(blocks.get(key) ?? []), q]);
    }
    return { ...g, count: qs.length, blocks: Array.from(blocks.entries()) };
  }), [all]);

  const onPatch = async (qid: string, body: { status?: string; body?: string }) => {
    try {
      await patch(`/api/research/${d.id}/queries/${qid}`, body);
      toast({ tone: "success", message: body.body ? "Query saved" : body.status === "generated" ? "Issue reported; query moved back to Generated" : `Query marked ${body.status}` });
      await reload();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
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
    <div className="space-y-8">
      {missingPlatforms.length > 0 && (
        <Alert tone="info" title={`No queries for ${workspace!.name}'s ${missingPlatforms.map((p) => platformName(p, true)).join(", ")}`}
          action={canEdit && <Button size="sm" icon={<RefreshCw />} loading={busy} onClick={() => generate(missingPlatforms)}>Generate {missingPlatforms.map((p) => platformName(p, true)).join(", ")} queries</Button>}>
          This run generated {rec.hunts.platforms.map((p) => platformName(p, true)).join(", ")} only. Re-running query generation reuses the existing sources and analysis.
        </Alert>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <Segmented ariaLabel="Query type" value={type} onChange={setType} options={[
          { value: "all", label: <>All <CountBadge>{all.length}</CountBadge></> },
          ...grouped.filter((g) => g.count).map((g) => ({ value: g.type, label: <>{g.type === "reference" ? "Vendor" : QUERY_TYPE[g.type]} <CountBadge>{g.count}</CountBadge></> })),
        ]} />
        <span className="text-caption text-fg-muted">Look-back {rec.hunts.lookback_days} days · {workspace ? `field mappings for ${workspace.name} applied on copy` : "select a workspace to apply its field mappings"}</span>
        <Button size="sm" className="ml-auto" icon={<Download />} onClick={() => download(`/api/research/${d.id}/export/queries_csv${ws !== "all" ? `?ws=${ws}` : ""}`)}>Queries CSV</Button>
      </div>

      {grouped.filter((g) => g.count && (type === "all" || type === g.type)).map((g) => (
        <section key={g.type}>
          <div className="mb-3 flex items-baseline gap-3">
            <h2 className="text-h2 font-semibold">{g.label}</h2>
            <span className="text-body-sm text-fg-muted">{g.help}</span>
          </div>
          <div className="space-y-4">
            {g.blocks.map(([key, qs]) => (
              <QueryBlock key={key} title={qs[0].title} refId={qs[0].opportunity_id} queries={qs} workspace={workspace}
                gaps={gapsFor(qs[0].opportunity_id)} onPatch={canEdit ? onPatch : undefined} canEdit={canEdit} />
            ))}
          </div>
        </section>
      ))}

      {rec.log_sources_required.length > 0 && (
        <section>
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
