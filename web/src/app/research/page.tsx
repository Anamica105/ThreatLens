"use client";

import { Archive, ArrowDown, ArrowUp, ArrowUpDown, Download, FileSearch, Mail, Plus, SearchX } from "lucide-react";
import { ChipList } from "@/components/chip-list";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { FilterTrigger, type ActiveChip } from "@/components/filters";
import { CardGrid, LibraryEmpty, LibraryLayout, TableShell, type FilterDef } from "@/components/library";
import { useApp, useWsHref } from "@/components/providers";
import { ResearchCard } from "@/components/research/research-card";
import { Avatar, ResultPill, SeverityBadge, StatusPill } from "@/components/ui/badges";
import { Button, ButtonLink } from "@/components/ui/button";
import { ErrorState, Skeleton, SkeletonRows, useToast } from "@/components/ui/feedback";
import { Checkbox, Input } from "@/components/ui/forms";
import { Page, PageHeader, Pagination } from "@/components/ui/layout";
import { Dialog, Popover, Tooltip } from "@/components/ui/overlay";
import { post, qs } from "@/lib/api";
import { CLASSIFICATION, CLASSIFICATION_FILTERS, CLASSIFICATION_NAMES, RESEARCH_STATUS, RESULT_STATUS, SEVERITY, SEVERITIES } from "@/lib/constants";
import { relative, utc } from "@/lib/format";
import { useApi, useDebounced, useLocalStorage } from "@/lib/hooks";
import type { ResearchSummary } from "@/lib/types";

type List = { total: number; items: ResearchSummary[] };
const SORTS = [
  { value: "-created_at", label: "Newest" }, { value: "created_at", label: "Oldest" }, { value: "-updated_at", label: "Recently updated" },
  { value: "-severity", label: "Severity" }, { value: "title", label: "Title A–Z" },
];

export default function ResearchLibrary() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const { ws, meta, activeWorkspace, workspaces } = useApp();
  const wsHref = useWsHref();
  const toast = useToast();
  const [view, setView] = useLocalStorage<"cards" | "list">("tl.view.research", "cards");
  const [q, setQ] = useState(params.get("q") ?? "");
  const dq = useDebounced(q, 300);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [selected, setSelected] = useState<string[]>([]);
  const [confirmArchive, setConfirmArchive] = useState(false);
  const sort = params.get("sort") ?? "-created_at";

  const get = (k: string) => params.getAll(k);
  const setParam = (k: string, v: string[] | string | null) => {
    const p = new URLSearchParams(params.toString());
    p.delete(k);
    if (Array.isArray(v)) v.forEach((x) => p.append(k, x));
    else if (v) p.set(k, v);
    setPage(1);
    router.replace(`${pathname}?${p.toString()}`, { scroll: false });
  };

  const apiUrl = `/api/research${qs({
    ws, q: dq, status: get("status"), severity: get("severity"), classification: get("classification"), result: get("result"),
    actor: params.get("actor"), industry: params.get("industry"), platform: params.get("platform"), author: params.get("author"),
    cve: params.get("cve"), technique: params.get("technique"), tactic: params.get("tactic"), from: params.get("from"), to: params.get("to"),
    sort, page, page_size: pageSize,
  })}`;
  const { data, error, loading, reload } = useApi<List>(apiUrl);
  // Actor and industry options come from the research in scope (one light request, independent of the other filters).
  const { data: facetData } = useApi<List>(`/api/research${qs({ ws, page_size: 1000 })}`);
  const facets = useMemo(() => {
    const rows = facetData?.items ?? [];
    const sorted = (xs: string[]) => Array.from(new Set(xs.filter(Boolean))).sort((a, b) => a.localeCompare(b));
    return { actors: sorted(rows.flatMap((r) => r.actors)), industries: sorted(rows.flatMap((r) => r.industries)) };
  }, [facetData]);
  const withCurrent = (xs: string[], cur: string | null) => (cur && !xs.some((x) => x.toLowerCase() === cur.toLowerCase()) ? [cur, ...xs] : xs);

  // Filters with a popover in the filter bar; their chips are derived by LibraryLayout.
  const one = (k: string) => (params.get(k) ? [params.get(k)!] : []);
  const filters: FilterDef[] = [
    { key: "status", label: "Status", values: get("status"), onChange: (v) => setParam("status", v), options: Object.entries(RESEARCH_STATUS).map(([k, v]) => ({ value: k, label: v.label })) },
    { key: "severity", label: "Severity", values: get("severity"), onChange: (v) => setParam("severity", v), options: SEVERITIES.map((s) => ({ value: s, label: SEVERITY[s].label, dot: SEVERITY[s].solid })) },
    { key: "classification", label: "Classification", values: get("classification"), onChange: (v) => setParam("classification", v), options: CLASSIFICATION_FILTERS.map((c) => ({ value: c, label: CLASSIFICATION_NAMES[c], dot: CLASSIFICATION[c].color })) },
    { key: "result", label: "Result", values: get("result"), onChange: (v) => setParam("result", v), options: Object.entries(RESULT_STATUS).map(([k, v]) => ({ value: k, label: v.label })) },
    { key: "actor", label: "Actor", single: true, values: one("actor"), onChange: (v) => setParam("actor", v[0] ?? null), options: withCurrent(facets.actors, params.get("actor")).map((a) => ({ value: a, label: a })) },
    { key: "industry", label: "Industry", single: true, values: one("industry"), onChange: (v) => setParam("industry", v[0] ?? null), options: withCurrent(facets.industries, params.get("industry")).map((i) => ({ value: i, label: i })) },
    { key: "platform", label: "Platform", single: true, values: one("platform"), onChange: (v) => setParam("platform", v[0] ?? null), options: (meta?.platforms ?? []).map((p) => ({ value: p.id, label: p.name })) },
    { key: "author", label: "Author", single: true, values: one("author"), onChange: (v) => setParam("author", v[0] ?? null), options: (meta?.users ?? []).map((u) => ({ value: u.id, label: u.name })) },
  ];

  // URL-only filters (reached from chips, dashboard tiles and entity pages) show as chips only.
  const chips = useMemo(() => {
    const out: ActiveChip[] = [];
    for (const [k, label] of [["cve", "CVE"], ["technique", "Technique"], ["tactic", "Tactic"]] as const) {
      const v = params.get(k);
      if (v) out.push({ key: k, label: `${label}: ${k === "tactic" ? meta?.tactics.find((t) => t.id === v)?.name ?? v : v}`, onRemove: () => setParam(k, null) });
    }
    if (params.get("from") || params.get("to")) out.push({ key: "date", label: `Created: ${params.get("from") ?? "…"} – ${params.get("to") ?? "…"}`, onRemove: () => { const p = new URLSearchParams(params.toString()); p.delete("from"); p.delete("to"); router.replace(`${pathname}?${p}`); } });
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params, meta]);

  const clearAll = () => router.replace(`${pathname}${ws !== "all" ? `?ws=${ws}` : ""}`);
  const items = data?.items ?? [];
  const allSel = items.length > 0 && items.every((i) => selected.includes(i.id));
  const toggleSort = (key: string) => setParam("sort", sort === `-${key}` ? key : `-${key}`);

  const exportSelected = () => {
    const rows = items.filter((i) => selected.includes(i.id));
    const head = ["id", "title", "status", "severity", "classification", "actors", "cves", "industries", "created_at"];
    const csv = [head.join(","), ...rows.map((r) => [r.id, r.title, r.status, r.severity, r.classification.join(" "), r.actors.join(" "), r.cves.join(" "), r.industries.join(" "), r.created_at]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))].join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob(["﻿" + csv], { type: "text/csv" }));
    a.download = `threatlens-selected-${rows.length}.csv`;
    a.click();
    toast({ tone: "success", message: `Exported ${rows.length} research record${rows.length === 1 ? "" : "s"}` });
  };

  const archive = async () => {
    const r = await post<{ archived: number }>("/api/research/bulk", { ids: selected, action: "archive" });
    setConfirmArchive(false);
    setSelected([]);
    toast({ tone: "success", message: `Archived ${r.archived} research record${r.archived === 1 ? "" : "s"}` });
    reload();
  };

  const filtered = chips.length > 0 || filters.some((f) => f.values.length > 0) || !!dq;
  const setDate = (f: string | null, t: string | null) => { const p = new URLSearchParams(params.toString()); p.delete("from"); p.delete("to"); if (f) p.set("from", f); if (t) p.set("to", t); setPage(1); router.replace(`${pathname}?${p}`, { scroll: false }); };

  return (
    <Page>
      <PageHeader title="Research" description={activeWorkspace ? `Research in scope for ${activeWorkspace.name}` : "All research across workspaces"}
        actions={<>
          <ButtonLink href={wsHref("/research/intake")} icon={<Mail />}>Import email</ButtonLink>
          <ButtonLink href={wsHref("/research/new")} variant="primary" icon={<Plus />}>Start research</ButtonLink>
        </>} />

      <LibraryLayout storageKey="research" search={q} onSearch={(v) => { setQ(v); setPage(1); }} searchLabel="Search title, summary, IoCs, CVEs"
        view={view} onView={setView} sort={sort} onSort={(v) => setParam("sort", v)} sortOptions={SORTS}
        filters={filters} extraChips={chips} onClearAll={() => { setQ(""); clearAll(); }}
        filterExtras={<DateFilter from={params.get("from")} to={params.get("to")} onChange={setDate} />}
        total={data?.total} noun={["research record", "research records"]}
        toolbarOverride={selected.length > 0 ? (
          <div className="flex min-h-9 flex-wrap items-center gap-x-3 gap-y-2 rounded-sm bg-accent-soft px-3 py-1">
            <span className="text-[14px] font-semibold">{selected.length} selected</span>
            <Button size="sm" icon={<Download />} onClick={exportSelected}>Export</Button>
            <Button size="sm" variant="danger-secondary" icon={<Archive />} onClick={() => setConfirmArchive(true)}>Archive</Button>
            <button onClick={() => setSelected([])} className="ml-auto text-[13px] font-semibold text-accent-text hover:underline">Clear selection</button>
          </div>
        ) : undefined}>
        {error ? <ErrorState error={error} onRetry={reload} /> : !data && loading ? (
          view === "cards" ? <CardGrid min={320}>{Array.from({ length: 6 }).map((_, i) => <div key={i} className="h-52 rounded-md border border-line bg-surface p-4"><Skeleton className="h-3 w-1/3" /><Skeleton className="mt-4 h-4 w-4/5" /><Skeleton className="mt-2 h-4 w-3/5" /><Skeleton className="mt-6 h-1.5 w-full" /></div>)}</CardGrid>
            : <div className="rounded-md border border-line bg-surface"><SkeletonRows /></div>
        ) : items.length === 0 ? (
          filtered ? <LibraryEmpty icon={<SearchX />} title="No research matches these filters" body="Try a wider date range or remove a filter." action={<Button onClick={() => { setQ(""); clearAll(); }}>Clear filters</Button>} />
            : <LibraryEmpty icon={<FileSearch />} title="No research yet" body="Paste a threat headline or CVE to start the first run." action={<ButtonLink href={wsHref("/research/new")} variant="primary" size="lg">Start research</ButtonLink>} />
        ) : view === "cards" ? (
          <>
            <CardGrid min={320}>{items.map((r) => <ResearchCard key={r.id} r={r} />)}</CardGrid>
            {data && data.total > pageSize && <Pagination page={page} pageSize={pageSize} total={data.total} onPage={setPage} />}
          </>
        ) : (
          <TableShell footer={data && <Pagination page={page} pageSize={pageSize} total={data.total} onPage={setPage} onPageSize={(n) => { setPageSize(n); setPage(1); }} />}>
            <table className="tl-table tl-comfortable w-full">
              <thead>
                <tr>
                  <th className="sticky left-0 z-[2] w-10"><Checkbox checked={allSel} indeterminate={selected.length > 0 && !allSel} onChange={(v) => setSelected(v ? items.map((i) => i.id) : [])} label={<span className="sr-only">Select page</span>} /></th>
                  <SortTh label="ID" k="id" sort={sort} onSort={toggleSort} />
                  <SortTh label="Title" k="title" sort={sort} onSort={toggleSort} />
                  <SortTh label="Status" k="status" sort={sort} onSort={toggleSort} />
                  <SortTh label="Severity" k="severity" sort={sort} onSort={toggleSort} />
                  <th>Classification</th><th>Actors</th><th>CVEs</th><th>Industries</th>
                  {activeWorkspace && <th>Result</th>}
                  <SortTh label="Created" k="created_at" sort={sort} onSort={toggleSort} />
                  <th>Author</th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.id} aria-selected={selected.includes(r.id)}>
                    <td className="sticky left-0 z-[1] bg-surface"><Checkbox checked={selected.includes(r.id)} onChange={(v) => setSelected(v ? [...selected, r.id] : selected.filter((x) => x !== r.id))} label={<span className="sr-only">Select {r.id}</span>} /></td>
                    <td className="whitespace-nowrap"><Link href={wsHref(`/research/${r.id}`)} className="font-mono text-mono-sm text-accent-text hover:underline">{r.id}</Link></td>
                    <td className="max-w-[360px] min-w-[200px]"><Tooltip content={r.title}><Link href={wsHref(`/research/${r.id}`)} className="block truncate hover:underline">{r.title}</Link></Tooltip></td>
                    <td><StatusPill status={r.status} /></td>
                    <td><SeverityBadge severity={r.severity} /></td>
                    <td><ChipList items={r.classification.map((c) => CLASSIFICATION_NAMES[c] ?? c)} /></td>
                    <td><ChipList items={r.actors} /></td>
                    <td><ChipList items={r.cves} mono /></td>
                    <td><ChipList items={r.industries} /></td>
                    {activeWorkspace && <td>{r.result ? <ResultPill status={r.result.status} /> : <span className="text-fg-faint">—</span>}</td>}
                    <td className="whitespace-nowrap"><Tooltip content={utc(r.created_at)}><span>{relative(r.created_at)}</span></Tooltip></td>
                    <td><span className="flex items-center gap-2 whitespace-nowrap"><Avatar initials={r.author?.initials} size={20} />{r.author?.name}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableShell>
        )}
      </LibraryLayout>
      <Dialog open={confirmArchive} onClose={() => setConfirmArchive(false)} size="sm" title={`Archive ${selected.length} research record${selected.length === 1 ? "" : "s"}?`}
        footer={<><Button onClick={() => setConfirmArchive(false)}>Cancel</Button><Button variant="danger" onClick={archive}>Archive</Button></>}>
        <p>Archived research leaves the library and dashboards. It stays searchable in the archive and can be restored.</p>
      </Dialog>
      {workspaces.length === 0 && null}
    </Page>
  );
}

function SortTh({ label, k, sort, onSort }: { label: string; k: string; sort: string; onSort: (k: string) => void }) {
  const active = sort.replace("-", "") === k;
  const desc = sort.startsWith("-");
  return (
    <th aria-sort={active ? (desc ? "descending" : "ascending") : "none"}>
      <button onClick={() => onSort(k)} className="group inline-flex items-center gap-1">
        {label}
        {active ? (desc ? <ArrowDown className="size-3.5 text-accent" /> : <ArrowUp className="size-3.5 text-accent" />) : <ArrowUpDown className="size-3.5 opacity-0 group-hover:opacity-100" />}
      </button>
    </th>
  );
}

function DateFilter({ from, to, onChange }: { from: string | null; to: string | null; onChange: (f: string | null, t: string | null) => void }) {
  const today = new Date();
  const iso = (d: Date) => d.toISOString().slice(0, 10);
  const presets: [string, () => [string, string]][] = [
    ["Last 7 days", () => [iso(new Date(Date.now() - 6 * 864e5)), iso(today)]],
    ["This month", () => [iso(new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1))), iso(today)]],
    ["This quarter", () => [iso(new Date(Date.UTC(today.getUTCFullYear(), Math.floor(today.getUTCMonth() / 3) * 3, 1))), iso(today)]],
    ["Year to date", () => [iso(new Date(Date.UTC(today.getUTCFullYear(), 0, 1))), iso(today)]],
  ];
  return (
    <FilterDate from={from} to={to} presets={presets} onChange={onChange} />
  );
}

function FilterDate({ from, to, presets, onChange }: { from: string | null; to: string | null; presets: [string, () => [string, string]][]; onChange: (f: string | null, t: string | null) => void }) {
  const [f, setF] = useState(from ?? "");
  const [t, setT] = useState(to ?? "");
  return (
    <FilterButtonShell label={from || to ? `Created: ${from ?? "…"} – ${to ?? "…"}` : "Created"} active={!!(from || to)}>
      {(close) => (
        <div className="flex flex-wrap gap-3 p-3">
          <div className="flex w-32 flex-col gap-0.5">
            {presets.map(([label, fn]) => (
              <button key={label} onClick={() => { const [a, b] = fn(); onChange(a, b); close(); }} className="rounded-sm px-2 py-1.5 text-left text-[13px] hover:bg-subtle">{label}</button>
            ))}
          </div>
          <div className="flex flex-col gap-2 border-l border-line pl-3">
            <label className="text-caption text-fg-muted">From<Input type="date" value={f} onChange={(e) => setF(e.target.value)} /></label>
            <label className="text-caption text-fg-muted">To<Input type="date" value={t} onChange={(e) => setT(e.target.value)} /></label>
            <Button size="sm" variant="primary" onClick={() => { onChange(f || null, t || null); close(); }}>Apply</Button>
          </div>
        </div>
      )}
    </FilterButtonShell>
  );
}

function FilterButtonShell({ label, active, children }: { label: string; active: boolean; children: (close: () => void) => React.ReactNode }) {
  return (
    <Popover width={360} label={label} trigger={(p) => <FilterTrigger {...p} label={label} active={active} />}>{children}</Popover>
  );
}
