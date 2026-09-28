"use client";

import { UserRoundSearch } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { CardLink, LibraryLayout, RailGroup } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { AttackChip, Chip } from "@/components/ui/badges";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/feedback";
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
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "Threat actors" }]} title="Threat actors" description="Built automatically from research runs; profiles are editable." />
      <LibraryLayout search={q} onSearch={setQ} searchLabel="Search actors and aliases" sort={sort} onSort={setSort} view={view} onView={setView}
        sortOptions={[{ value: "last_seen", label: "Last seen" }, { value: "research", label: "Most research" }, { value: "name", label: "Name" }]}
        activeFilters={[origin, motivation, industry].filter(Boolean).length}
        filters={<>
          <RailGroup label="Origin" options={facets?.origin ?? []} value={origin} onChange={setOrigin} />
          <RailGroup label="Motivation" options={facets?.motivation ?? []} value={motivation} onChange={setMotivation} />
          <RailGroup label="Industries" options={facets?.industry ?? []} value={industry} onChange={setIndustry} />
        </>}>
        {error ? <ErrorState error={error} onRetry={reload} /> : !data ? <SkeletonRows /> : !data.items.length ? (
          <EmptyState icon={<UserRoundSearch />} title="No threat actors yet" body="Actors are added when a research run attributes activity." />
        ) : view === "cards" ? (
          <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
            {data.items.map((a) => (
              <CardLink key={a.id} href={wsHref(`/library/actors/${a.id}`)}>
                <div className="flex items-start justify-between gap-2">
                  <h3 className="text-h3 font-semibold">{a.name}</h3>
                  {a.origin && <Chip>{a.origin}</Chip>}
                </div>
                <p className="truncate text-body-sm text-fg-muted">{a.aliases.length ? a.aliases.join(", ") : "No known aliases"}</p>
                <div className="flex flex-wrap gap-1.5">{a.motivation.map((m) => <Chip key={m}>{m}</Chip>)}</div>
                <div className="relative z-[1] flex flex-wrap gap-1.5">{a.top_techniques.map((t) => <AttackChip key={t.id} id={t.id} name={t.name.split(": ").pop()} />)}</div>
                <div className="mt-auto border-t border-line pt-3 text-caption text-fg-muted">
                  Seen in {a.research_count} research · last seen <span title={utc(a.last_seen)}>{relative(a.last_seen)}</span>
                </div>
              </CardLink>
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-md border border-line bg-surface">
            <table className="tl-table tl-comfortable w-full">
              <thead><tr><th>Name</th><th>Aliases</th><th>Origin</th><th>Motivation</th><th className="num">Research</th><th>Last seen</th></tr></thead>
              <tbody>{data.items.map((a) => (
                <tr key={a.id}>
                  <td><Link href={wsHref(`/library/actors/${a.id}`)} className="font-semibold hover:underline">{a.name}</Link></td>
                  <td className="max-w-[260px] truncate text-fg-muted">{a.aliases.join(", ") || "—"}</td>
                  <td>{a.origin || "—"}</td><td>{a.motivation.join(", ") || "—"}</td>
                  <td className="num">{a.research_count}</td><td title={utc(a.last_seen)}>{relative(a.last_seen)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </LibraryLayout>
    </Page>
  );
}
