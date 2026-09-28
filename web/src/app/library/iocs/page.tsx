"use client";

import { Fingerprint, SearchX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { CardFooter, CardGrid, CardLink, LibraryEmpty, LibraryLayout, TableShell, facetOptions, single } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { IocValue } from "@/components/research/ioc-value";
import { VerdictBadge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { ErrorState, SkeletonRows } from "@/components/ui/feedback";
import { Page, PageHeader, Pagination } from "@/components/ui/layout";
import { qs } from "@/lib/api";
import { IOC_TYPE_LABEL, VERDICT } from "@/lib/constants";
import { relative, utc } from "@/lib/format";
import { useApi, useDebounced, useLocalStorage } from "@/lib/hooks";
import type { Verdict } from "@/lib/types";

interface I { id: number; type: string; value: string; verdict: Verdict; reputation_summary: string; first_seen: string | null; last_seen: string | null; research_count: number; source_count: number; enriched_at: string | null }

const VERDICT_LABEL = Object.fromEntries(Object.entries(VERDICT).map(([k, v]) => [k, v.label]));

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
  const reset = <T,>(set: (v: T) => void) => (v: T) => { set(v); setPage(1); };
  const filtered = !!(dq || type || verdict);
  const clear = () => { setQ(""); setType(""); setVerdict(""); setPage(1); };
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "IoCs" }]} title="IoCs" description="Every indicator from every run, defanged, with OSINT reputation and a single verdict." />
      <LibraryLayout storageKey="iocs" search={q} onSearch={reset(setQ)} searchLabel="Search indicators (defanged is fine)" view={view} onView={setView}
        total={data?.total} noun={["indicator", "indicators"]} onClearAll={clear}
        filters={[
          { key: "type", label: "Type", options: facetOptions(data?.facets.type, IOC_TYPE_LABEL), ...single(type, reset(setType)) },
          { key: "verdict", label: "Verdict", options: facetOptions(data?.facets.verdict, VERDICT_LABEL), ...single(verdict, reset(setVerdict)) },
        ]}>
        {error ? <ErrorState error={error} onRetry={reload} /> : !data ? <SkeletonRows rows={8} height={36} /> : !data.items.length ? (
          filtered ? <LibraryEmpty icon={<SearchX />} title="No indicators match" body="Try another value or remove a filter. Defanged input is fine." action={<Button onClick={clear}>Clear filters</Button>} />
            : <LibraryEmpty icon={<Fingerprint />} title="No indicators yet" body="Indicators are extracted from sources during research runs." />
        ) : view === "cards" ? (
          <>
            <CardGrid>
              {data.items.map((i) => (
                <CardLink key={i.id} href={wsHref(`/library/iocs/${i.id}`)} label={i.value}>
                  <div className="relative z-[1] min-w-0"><IocValue type={i.type} value={i.value} compact /></div>
                  <div className="flex min-w-0 items-center gap-2"><VerdictBadge verdict={i.verdict} /><span className="min-w-0 truncate text-body-sm text-fg-muted" title={i.reputation_summary}>{i.reputation_summary || "Not enriched"}</span></div>
                  <CardFooter>
                    <span className="min-w-0 truncate tabular">×{i.source_count} sources · {i.research_count} research</span>
                    <span className="ml-auto shrink-0" title={utc(i.last_seen)}>{relative(i.last_seen)}</span>
                  </CardFooter>
                </CardLink>
              ))}
            </CardGrid>
            <Pagination page={page} pageSize={100} total={data.total} onPage={setPage} />
          </>
        ) : (
          <TableShell footer={<Pagination page={page} pageSize={100} total={data.total} onPage={setPage} />}>
            <table className="tl-table tl-compact w-full">
              <thead><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Reputation</th><th className="num">Sources</th><th className="num">Research</th><th>First seen</th><th>Last seen</th></tr></thead>
              <tbody>{data.items.map((i) => (
                <tr key={i.id} className="cursor-pointer" onClick={(e) => { if (!(e.target as HTMLElement).closest("button")) router.push(wsHref(`/library/iocs/${i.id}`)); }}>
                  <td className="max-w-[420px] min-w-[220px]"><IocValue type={i.type} value={i.value} compact onOpen={() => router.push(wsHref(`/library/iocs/${i.id}`))} /></td>
                  <td className="whitespace-nowrap">{IOC_TYPE_LABEL[i.type] ?? i.type}</td>
                  <td><VerdictBadge verdict={i.verdict} /></td>
                  <td className="max-w-[240px] truncate text-fg-muted" title={i.reputation_summary}>{i.reputation_summary || "Not enriched"}</td>
                  <td className="num font-mono">×{i.source_count}</td>
                  <td className="num">{i.research_count}</td>
                  <td className="whitespace-nowrap" title={utc(i.first_seen)}>{relative(i.first_seen)}</td>
                  <td className="whitespace-nowrap" title={utc(i.last_seen)}>{relative(i.last_seen)}</td>
                </tr>
              ))}</tbody>
            </table>
          </TableShell>
        )}
      </LibraryLayout>
    </Page>
  );
}
