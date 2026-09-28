"use client";

import { SearchX, UserRoundSearch } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { CardFooter, CardGrid, CardHeader, CardLink, LibraryEmpty, LibraryLayout, TableShell, facetOptions, single } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { AttackChip, Chip } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { ErrorState, SkeletonRows } from "@/components/ui/feedback";
import { Page, PageHeader } from "@/components/ui/layout";
import { qs } from "@/lib/api";
import { relative, utc } from "@/lib/format";
import { useApi, useDebounced, useLocalStorage } from "@/lib/hooks";

interface ActorRow {
  id: string; name: string; aliases: string[]; origin: string; motivation: string[]; target_industries: string[]; target_regions: string[];
  research_count: number; first_seen: string | null; last_seen: string | null; top_techniques: { id: string; name: string; count: number }[];
}

export default function ActorsLibrary() {
  const wsHref = useWsHref();
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [origin, setOrigin] = useState("");
  const [motivation, setMotivation] = useState("");
  const [industry, setIndustry] = useState("");
  const [sort, setSort] = useState("last_seen");
  const [view, setView] = useLocalStorage<"cards" | "list">("tl.view.actors", "cards");
  const { data, error, reload } = useApi<{ items: ActorRow[]; facets: { origin: string[]; motivation: string[]; industry: string[] } }>(
    `/api/library/actors${qs({ q: dq, origin, motivation, industry, sort })}`);
  const facets = data?.facets;
  const filtered = !!(dq || origin || motivation || industry);
  const clear = () => { setQ(""); setOrigin(""); setMotivation(""); setIndustry(""); };
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "Threat actors" }]} title="Threat actors" description="Built automatically from research runs; profiles are editable." />
      <LibraryLayout storageKey="actors" search={q} onSearch={setQ} searchLabel="Search actors and aliases" sort={sort} onSort={setSort} view={view} onView={setView}
        sortOptions={[{ value: "last_seen", label: "Last seen" }, { value: "research", label: "Most research" }, { value: "name", label: "Name" }]}
        total={data?.items.length} noun={["actor", "actors"]} onClearAll={clear}
        filters={[
          { key: "origin", label: "Origin", options: facetOptions(facets?.origin), ...single(origin, setOrigin) },
          { key: "motivation", label: "Motivation", options: facetOptions(facets?.motivation), ...single(motivation, setMotivation) },
          { key: "industry", label: "Industry", options: facetOptions(facets?.industry), ...single(industry, setIndustry) },
        ]}>
        {error ? <ErrorState error={error} onRetry={reload} /> : !data ? <SkeletonRows /> : !data.items.length ? (
          filtered ? <LibraryEmpty icon={<SearchX />} title="No actors match these filters" body="Try another search term or remove a filter." action={<Button onClick={clear}>Clear filters</Button>} />
            : <LibraryEmpty icon={<UserRoundSearch />} title="No threat actors yet" body="Actors are added when a research run attributes activity." />
        ) : view === "cards" ? (
          <CardGrid>
            {data.items.map((a) => (
              <CardLink key={a.id} href={wsHref(`/library/actors/${a.id}`)} label={a.name}>
                <CardHeader title={a.name} icon={<UserRoundSearch />} sub={a.aliases.length ? a.aliases.join(", ") : "No known aliases"}
                  aside={a.origin ? <Chip>{a.origin}</Chip> : undefined} />
                {a.motivation.length > 0 && <div className="flex min-w-0 flex-wrap gap-1.5">{a.motivation.map((m) => <Chip key={m}>{m}</Chip>)}</div>}
                {a.top_techniques.length > 0 && (
                  <div className="relative z-[1] flex min-w-0 flex-col items-start gap-1.5">
                    {a.top_techniques.map((t) => <AttackChip key={t.id} id={t.id} name={t.name.split(": ").pop()} />)}
                  </div>
                )}
                <CardFooter>
                  <span className="truncate">Seen in {a.research_count} research</span>
                  <span className="ml-auto shrink-0" title={utc(a.last_seen)}>Last seen {relative(a.last_seen)}</span>
                </CardFooter>
              </CardLink>
            ))}
          </CardGrid>
        ) : (
          <TableShell>
            <table className="tl-table tl-comfortable w-full">
              <thead><tr><th>Name</th><th>Aliases</th><th>Origin</th><th>Motivation</th><th className="num">Research</th><th>Last seen</th></tr></thead>
              <tbody>{data.items.map((a) => (
                <tr key={a.id}>
                  <td className="whitespace-nowrap"><Link href={wsHref(`/library/actors/${a.id}`)} className="font-semibold hover:underline">{a.name}</Link></td>
                  <td className="max-w-[260px] truncate text-fg-muted" title={a.aliases.join(", ")}>{a.aliases.join(", ") || "—"}</td>
                  <td className="whitespace-nowrap">{a.origin || "—"}</td>
                  <td className="max-w-[220px] truncate" title={a.motivation.join(", ")}>{a.motivation.join(", ") || "—"}</td>
                  <td className="num">{a.research_count}</td><td className="whitespace-nowrap" title={utc(a.last_seen)}>{relative(a.last_seen)}</td>
                </tr>
              ))}</tbody>
            </table>
          </TableShell>
        )}
      </LibraryLayout>
    </Page>
  );
}
