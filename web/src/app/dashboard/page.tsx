"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { AttackHeatmap, CategoryBars, KpiTile, RankedList, RunsLine } from "@/components/charts";
import { useApp, useWsHref } from "@/components/providers";
import { ErrorState, Skeleton } from "@/components/ui/feedback";
import { Input, Select } from "@/components/ui/forms";
import { Page, PageHeader, Panel } from "@/components/ui/layout";
import { RESULT_STATUS, SEVERITY } from "@/lib/constants";
import { num, relative, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { ResultStatus, Severity } from "@/lib/types";

interface Dash {
  period: { label: string; from: string; to: string };
  kpis: Record<string, number | null>; previous: Record<string, number | null>;
  runs_over_time: { week: string; count: number }[];
  results_by_status: { status: ResultStatus; count: number }[];
  severity_mix: { severity: Severity; count: number }[];
  heatmap: { id: string; name: string; short: string; techniques: { id: string; name: string; count: number }[] }[];
  top_actors: { name: string; count: number }[]; top_cves: { cve: string; count: number; cvss: number | null }[];
  per_client: { id: string; name: string; color: string; industry: string; runs: number; findings: number; pending: number; last_report: { id: string; title: string; published_at: string } | null }[];
}

const PERIODS = [
  { value: "week", label: "This week" }, { value: "month", label: "This month" }, { value: "quarter", label: "This quarter" },
  { value: "last_quarter", label: "Last quarter" }, { value: "year", label: "Year to date" }, { value: "custom", label: "Custom range" },
];

function delta(cur: number | null | undefined, prev: number | null | undefined) {
  if (cur === null || cur === undefined || prev === null || prev === undefined) return null;
  if (prev === 0) return cur === 0 ? 0 : null;
  return ((cur - prev) / prev) * 100;
}

export default function DashboardPage() {
  const { ws, activeWorkspace } = useApp();
  const router = useRouter();
  const wsHref = useWsHref();
  const [period, setPeriod] = useState("quarter");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const q = new URLSearchParams({ period, ...(ws !== "all" ? { ws } : {}), ...(period === "custom" && from && to ? { date_from: from, date_to: to } : {}) });
  const { data, error, reload } = useApi<Dash>(`/api/dashboard?${q}`);
  const lib = (extra: string) => router.push(wsHref(`/research?from=${data?.period.from ?? ""}&to=${data?.period.to ?? ""}${extra}`));

  return (
    <Page>
      <PageHeader title="Dashboard" description={`${activeWorkspace?.name ?? "All workspaces"} · ${data?.period.label ?? "…"}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {period === "custom" && (
              <>
                <Input type="date" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="From" className="w-40" />
                <Input type="date" value={to} onChange={(e) => setTo(e.target.value)} aria-label="To" className="w-40" />
              </>
            )}
            <Select value={period} onChange={setPeriod} options={PERIODS} ariaLabel="Period" className="w-44" />
          </div>
        } />
      {error ? <ErrorState error={error} onRetry={reload} /> : !data ? <DashSkeleton /> : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
            <KpiTile label="Research runs completed" value={num(data.kpis.runs)} delta={delta(data.kpis.runs, data.previous.runs)} onClick={() => lib("")} />
            <KpiTile label="Published reports" value={num(data.kpis.published)} delta={delta(data.kpis.published, data.previous.published)} onClick={() => lib("&status=published")} />
            <KpiTile label="Median time to publish" value={data.kpis.median_hours_to_publish !== null ? `${data.kpis.median_hours_to_publish} h` : "—"}
              delta={delta(data.kpis.median_hours_to_publish, data.previous.median_hours_to_publish)} goodWhenUp={false} onClick={() => lib("&status=published")} />
            <KpiTile label="Hunts with findings" value={num(data.kpis.findings)} delta={delta(data.kpis.findings, data.previous.findings)} goodWhenUp={false} onClick={() => lib("&result=suspicious&result=confirmed")} />
            <KpiTile label="IoCs added" value={num(data.kpis.iocs, true)} tooltip={num(data.kpis.iocs)} delta={delta(data.kpis.iocs, data.previous.iocs)} onClick={() => router.push(wsHref("/library/iocs"))} />
            <KpiTile label="Queries generated" value={num(data.kpis.queries, true)} tooltip={num(data.kpis.queries)} delta={delta(data.kpis.queries, data.previous.queries)} onClick={() => router.push(wsHref("/library/queries"))} />
          </div>

          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Panel title="Research over time"><RunsLine data={data.runs_over_time} onPoint={() => lib("")} /></Panel>
            <Panel title="Results by status">
              <CategoryBars unit="hunt results" onBar={(k) => lib(`&result=${k}`)}
                data={data.results_by_status.map((r) => ({ key: r.status, label: RESULT_STATUS[r.status].label, count: r.count,
                  color: { confirmed: "var(--sev-critical)", suspicious: "var(--sev-medium)", no_evidence: "var(--success)", not_applicable: "var(--g-400)", pending: "var(--info)" }[r.status] }))} />
            </Panel>
          </div>

          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <Panel title="Severity mix">
              <CategoryBars onBar={(k) => lib(`&severity=${k}`)}
                data={data.severity_mix.map((s) => ({ key: s.severity, label: SEVERITY[s.severity].label, count: s.count, color: SEVERITY[s.severity].solid }))} />
            </Panel>
            <Panel title="ATT&CK tactic coverage">
              <AttackHeatmap tactics={data.heatmap} onCell={(t) => lib(`&technique=${t}`)} />
            </Panel>
          </div>

          <div className="grid gap-6 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] xl:grid-cols-[repeat(3,minmax(0,1fr))]">
            <Panel title="Top actors">
              <RankedList items={data.top_actors.map((a) => ({ key: a.name, label: a.name, count: a.count }))} onItem={(k) => lib(`&actor=${encodeURIComponent(k)}`)} />
            </Panel>
            <Panel title="Top CVEs">
              <RankedList items={data.top_cves.map((c) => ({ key: c.cve, label: c.cve, count: c.count, mono: true }))} onItem={(k) => lib(`&cve=${k}`)} />
            </Panel>
            <Panel title="By workspace" bodyClassName="!p-0" className="md:col-span-2 xl:col-span-1">
              <div className="overflow-x-auto">
              <table className="tl-table tl-compact w-full">
                <thead><tr><th>Workspace</th><th className="num">Runs</th><th className="num">Findings</th><th>Last report</th></tr></thead>
                <tbody>
                  {data.per_client.map((c) => (
                    <tr key={c.id}>
                      <td className="max-w-[180px]"><span className="flex min-w-0 items-center gap-2" title={c.name}><span className="size-2 shrink-0 rounded-full" style={{ background: c.color }} /><span className="truncate">{c.name}</span></span></td>
                      <td className="num">{c.runs}</td>
                      <td className="num">{c.findings ? <span className="font-semibold" style={{ color: "var(--warning)" }}>{c.findings}</span> : 0}</td>
                      <td className="whitespace-nowrap">{c.last_report ? <Link href={`/research/${c.last_report.id}?ws=${c.id}`} className="font-mono text-mono-sm text-accent-text hover:underline" title={utc(c.last_report.published_at)}>{c.last_report.id}</Link> : <span className="text-fg-faint">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            </Panel>
          </div>
          {activeWorkspace && data.per_client[0] && (
            <p className="text-caption text-fg-muted">
              {data.per_client[0].pending} hunt{data.per_client[0].pending === 1 ? "" : "s"} pending for {activeWorkspace.name} in this period.
              {data.per_client[0].last_report && <> Last report {relative(data.per_client[0].last_report.published_at)}.</>}
            </p>
          )}
        </div>
      )}
    </Page>
  );
}

function DashSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => <div key={i} className="rounded-md border border-line bg-surface p-4"><Skeleton className="h-3 w-3/5" /><Skeleton className="mt-3 h-7 w-1/3" /><Skeleton className="mt-3 h-3 w-2/5" /></div>)}
      </div>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">{[0, 1].map((i) => <div key={i} className="h-72 rounded-md border border-line bg-surface p-4"><Skeleton className="h-3 w-1/4" /><Skeleton className="mt-6 h-48 w-full" /></div>)}</div>
    </div>
  );
}
