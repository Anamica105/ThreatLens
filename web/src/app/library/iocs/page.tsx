"use client";

import { Fingerprint, SearchX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { CardFooter, CardGrid, CardLink, LibraryEmpty, LibraryLayout, TableShell, facetOptions, single } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { IocValue } from "@/components/research/ioc-value";
import { AnyVerdictBadge, VERDICT_LABEL as ANY_VERDICT_LABEL, type AnyVerdict, type IocOverride } from "@/components/research/detail/iocs-tab";
import { Badge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { ErrorState, SkeletonRows } from "@/components/ui/feedback";
import { Page, PageHeader, Pagination } from "@/components/ui/layout";
import { qs } from "@/lib/api";
import { IOC_TYPE_LABEL } from "@/lib/constants";
import { relative, utc } from "@/lib/format";
import { useApi, useDebounced, useLocalStorage } from "@/lib/hooks";

interface I {
  id: number; type: string; value: string; verdict: AnyVerdict; reputation_summary: string; first_seen: string | null; last_seen: string | null; research_count: number;
  source_count: number; enriched_at: string | null; expires_at: string | null; expired?: boolean; verdict_override: IocOverride | null;
}

const VERDICT_LABEL: Record<string, string> = ANY_VERDICT_LABEL;

function Expiry({ i }: { i: I }) {
  if (!i.expires_at) return <span className="text-fg-muted">Never</span>;
  return <span className={i.expired ? "text-fg-muted" : undefined} title={utc(i.expires_at)}>{i.expired ? "Expired " : ""}{utc(i.expires_at, false)}</span>;
}

function VerdictWithOverride({ i }: { i: I }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <AnyVerdictBadge verdict={i.verdict} />
      {i.verdict_override && <Badge title={`Analyst override${i.verdict_override.by ? ` by ${i.verdict_override.by_name ?? i.verdict_override.by}` : ""}${i.verdict_override.at ? `, ${utc(i.verdict_override.at)}` : ""}${i.verdict_override.note ? `: ${i.verdict_override.note}` : ""}`}>Override</Badge>}
    </span>
  );
}

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
                  <div className="flex min-w-0 items-center gap-2"><VerdictWithOverride i={i} /><span className="min-w-0 truncate text-body-sm text-fg-muted" title={i.reputation_summary}>{i.reputation_summary || "Not enriched"}</span></div>
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
              <thead><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Reputation</th><th className="num">Sources</th><th className="num">Research</th><th>First seen</th><th>Last seen</th><th>Expires</th></tr></thead>
              <tbody>{data.items.map((i) => (
                <tr key={i.id} className="cursor-pointer" onClick={(e) => { if (!(e.target as HTMLElement).closest("button")) router.push(wsHref(`/library/iocs/${i.id}`)); }}>
                  <td className="max-w-[420px] min-w-[220px]"><IocValue type={i.type} value={i.value} compact onOpen={() => router.push(wsHref(`/library/iocs/${i.id}`))} /></td>
                  <td className="whitespace-nowrap">{IOC_TYPE_LABEL[i.type] ?? i.type}</td>
                  <td><VerdictWithOverride i={i} /></td>
                  <td className="max-w-[240px] truncate text-fg-muted" title={i.reputation_summary}>{i.reputation_summary || "Not enriched"}</td>
                  <td className="num font-mono">×{i.source_count}</td>
                  <td className="num">{i.research_count}</td>
                  <td className="whitespace-nowrap" title={utc(i.first_seen)}>{relative(i.first_seen)}</td>
                  <td className="whitespace-nowrap" title={utc(i.last_seen)}>{relative(i.last_seen)}</td>
                  <td className="whitespace-nowrap"><Expiry i={i} /></td>
                </tr>
              ))}</tbody>
            </table>
          </TableShell>
        )}
      </LibraryLayout>
    </Page>
  );
}
