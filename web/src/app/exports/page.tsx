"use client";

import { Download, FileSpreadsheet, FileText, History, Sheet } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { useApp, useWsHref } from "@/components/providers";
import { Avatar, Badge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { EmptyState, useToast } from "@/components/ui/feedback";
import { Field, Input, Select } from "@/components/ui/forms";
import { Page, PageHeader, Panel } from "@/components/ui/layout";
import { Tooltip } from "@/components/ui/overlay";
import { download } from "@/lib/api";
import { relative, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { User } from "@/lib/types";

interface Hist { id: number; research_id: string | null; workspace: string; format: string; scope: string; params: Record<string, unknown>; file_name: string; user: User | null; created_at: string }

const FORMATS = [
  { id: "xlsx", label: "XLSX workbook", help: "Sheets: Runs, TTPs, IoCs, Queries", icon: <FileSpreadsheet /> },
  { id: "csv", label: "CSV", help: "Runs only, one row per research", icon: <Sheet /> },
  { id: "pdf", label: "Summary PDF", help: "KPI tiles and charts for the period", icon: <FileText /> },
];

export default function ExportsPage() {
  const params = useSearchParams();
  const { ws, workspaces } = useApp();
  const wsHref = useWsHref();
  const toast = useToast();
  const [scope, setScope] = useState(ws);
  const [period, setPeriod] = useState(params.get("period") ?? "month");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const { data: hist, reload } = useApi<Hist[]>("/api/exports/history");

  const run = async (format: string) => {
    if (period === "custom" && (!from || !to)) { toast({ tone: "warning", message: "Choose both dates for a custom range" }); return; }
    setBusy(format);
    try {
      const name = await download("/api/exports/period", { method: "POST", json: { ws: scope, period, date_from: from || null, date_to: to || null, format } });
      toast({ tone: "success", message: `Exported ${name}` });
      reload();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(null); }
  };

  return (
    <Page>
      <PageHeader title="Exports" description="Period exports for hunt leads and QBRs, and the history of every export sent." />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
        <Panel title="Period export">
          <div className="space-y-5">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Workspace" htmlFor="ex-ws">
                <Select id="ex-ws" value={scope} onChange={setScope} options={[{ value: "all", label: "All workspaces" }, ...workspaces.map((w) => ({ value: w.id, label: w.name }))]} />
              </Field>
              <Field label="Period" htmlFor="ex-p">
                <Select id="ex-p" value={period} onChange={setPeriod} options={[
                  { value: "week", label: "Weekly (this week)" }, { value: "month", label: "Monthly (this month)" }, { value: "quarter", label: "Quarterly (this quarter)" },
                  { value: "last_quarter", label: "Last quarter" }, { value: "year", label: "Year to date" }, { value: "custom", label: "Custom range" }]} />
              </Field>
            </div>
            {period === "custom" && (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="From" htmlFor="ex-f"><Input id="ex-f" type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
                <Field label="To" htmlFor="ex-t"><Input id="ex-t" type="date" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
              </div>
            )}
            <div className="grid gap-3 sm:grid-cols-3">
              {FORMATS.map((f) => (
                <div key={f.id} className="flex flex-col gap-2 rounded-md border border-line p-3">
                  <span className="flex items-center gap-2 text-h4 font-semibold [&_svg]:size-5 [&_svg]:text-fg-muted">{f.icon}{f.label}</span>
                  <span className="flex-1 text-caption text-fg-muted">{f.help}</span>
                  <Button size="sm" icon={<Download />} loading={busy === f.id} onClick={() => run(f.id)}>Export {f.id.toUpperCase()}</Button>
                </div>
              ))}
            </div>
            <p className="text-caption text-fg-muted">Exports use absolute UTC dates. Every export is logged below with who, what, when and which workspace.</p>
          </div>
        </Panel>

        <Panel title="Export history" bodyClassName="!p-0">
          {!hist?.length ? <EmptyState icon={<History />} title="No exports yet" body="Exports from research pages and period exports appear here." /> : (
            <div className="max-h-[560px] overflow-auto">
              <table className="tl-table tl-compact w-full">
                <thead><tr><th>File</th><th>Scope</th><th>Workspace</th><th>By</th><th>When</th></tr></thead>
                <tbody>
                  {hist.map((h) => (
                    <tr key={h.id}>
                      <td className="max-w-[240px] truncate">
                        {h.research_id ? <Link href={wsHref(`/research/${h.research_id}`)} className="font-mono text-mono-sm text-accent-text hover:underline">{h.file_name || h.research_id}</Link>
                          : <span className="font-mono text-mono-sm">{h.file_name}</span>}
                      </td>
                      <td><Badge>{h.scope === "period" ? `Period · ${String(h.params.from ?? "")} – ${String(h.params.to ?? "")}` : h.format.toUpperCase().replace("_", " ")}</Badge></td>
                      <td>{h.workspace}</td>
                      <td><span className="flex items-center gap-1.5 whitespace-nowrap"><Avatar initials={h.user?.initials} size={20} />{h.user?.name ?? "—"}</span></td>
                      <td className="whitespace-nowrap"><Tooltip content={utc(h.created_at)}><span>{relative(h.created_at)}</span></Tooltip></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </Page>
  );
}
