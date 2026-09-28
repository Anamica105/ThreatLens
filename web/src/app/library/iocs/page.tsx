"use client";

import { Fingerprint } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { CardLink, LibraryLayout, RailGroup } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { IocValue } from "@/components/research/ioc-value";
import { VerdictBadge } from "@/components/ui/badges";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/feedback";
import { Page, PageHeader, Pagination } from "@/components/ui/layout";
import { qs } from "@/lib/api";
import { IOC_TYPE_LABEL } from "@/lib/constants";
import { relative, utc } from "@/lib/format";
import { useApi, useDebounced, useLocalStorage } from "@/lib/hooks";
import type { Verdict } from "@/lib/types";

interface I { id: number; type: string; value: string; verdict: Verdict; reputation_summary: string; first_seen: string | null; last_seen: string | null; research_count: number; source_count: number; enriched_at: string | null }

export default function IocLibrary() {
  const wsHref = useWsHref();
  const router = useRouter();
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [type, setType] = useState("");
  const [verdict, setVerdict] = useState("");
  const [page, setPage] = useState(1);
  const [view, setView] = useLocalStorage<"cards" | "list">("tl.view.iocs", "list");
  const { data, error, reload } = useApi<{ total: number; items: I[]; facets: { type: string[]; verdict: string[] } }>(`/api/library/iocs${qs({ q: dq, type, verdict, page, page_size: 100 })}`);
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "IoCs" }]} title="IoCs" description="Every indicator from every run, defanged, with OSINT reputation and a single verdict." />
      <LibraryLayout search={q} onSearch={(v) => { setQ(v); setPage(1); }} searchLabel="Search indicators (defanged is fine)" view={view} onView={setView}
        activeFilters={[type, verdict].filter(Boolean).length}
        filters={<>
          <RailGroup label="Type" options={data?.facets.type ?? []} value={type} onChange={(v) => { setType(v); setPage(1); }} />
          <RailGroup label="Verdict" options={data?.facets.verdict ?? []} value={verdict} onChange={(v) => { setVerdict(v); setPage(1); }} />
        </>}>
        {error ? <ErrorState error={error} onRetry={reload} /> : !data ? <SkeletonRows rows={8} height={36} /> : !data.items.length ? (
          <EmptyState icon={<Fingerprint />} title="No indicators match" body="Indicators are extracted from sources during research runs." />
        ) : view === "cards" ? (
          <>
            <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
              {data.items.map((i) => (
                <CardLink key={i.id} href={wsHref(`/library/iocs/${i.id}`)}>
                  <div className="relative z-[1]"><IocValue type={i.type} value={i.value} compact /></div>
                  <div className="flex items-center gap-2"><VerdictBadge verdict={i.verdict} /><span className="truncate text-body-sm text-fg-muted">{i.reputation_summary || "Not enriched"}</span></div>
                  <div className="mt-auto border-t border-line pt-3 text-caption text-fg-muted">×{i.source_count} sources · {i.research_count} research · last seen {relative(i.last_seen)}</div>
                </CardLink>
              ))}
            </div>
            <Pagination page={page} pageSize={100} total={data.total} onPage={setPage} />
          </>
        ) : (
          <div className="rounded-md border border-line bg-surface">
            <div className="overflow-x-auto">
              <table className="tl-table tl-compact w-full">
                <thead><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Reputation</th><th className="num">Sources</th><th className="num">Research</th><th>First seen</th><th>Last seen</th></tr></thead>
                <tbody>{data.items.map((i) => (
                  <tr key={i.id} className="cursor-pointer" onClick={(e) => { if (!(e.target as HTMLElement).closest("button")) router.push(wsHref(`/library/iocs/${i.id}`)); }}>
                    <td className="max-w-[420px]"><IocValue type={i.type} value={i.value} compact onOpen={() => router.push(wsHref(`/library/iocs/${i.id}`))} /></td>
                    <td>{IOC_TYPE_LABEL[i.type] ?? i.type}</td>
                    <td><VerdictBadge verdict={i.verdict} /></td>
                    <td className="max-w-[240px] truncate text-fg-muted">{i.reputation_summary || "Not enriched"}</td>
                    <td className="num font-mono">×{i.source_count}</td>
                    <td className="num">{i.research_count}</td>
                    <td className="whitespace-nowrap" title={utc(i.first_seen)}>{relative(i.first_seen)}</td>
                    <td className="whitespace-nowrap" title={utc(i.last_seen)}>{relative(i.last_seen)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={100} total={data.total} onPage={setPage} />
          </div>
        )}
      </LibraryLayout>
    </Page>
  );
}
