"use client";

import clsx from "clsx";
import { Filter, LayoutGrid, List, Search } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { relative, utc } from "@/lib/format";
import { useWsHref } from "./providers";
import { SeverityBadge, StatusPill } from "./ui/badges";
import { Input, Segmented, Select } from "./ui/forms";
import { Panel } from "./ui/layout";
import { Dialog, Tooltip } from "./ui/overlay";
import type { ResearchStatus, Severity } from "@/lib/types";

/** Shared library layout (design.md 25.3): filter rail, search, sort, cards/list toggle. */
export function LibraryLayout({ filters, search, onSearch, searchLabel, sort, onSort, sortOptions, view, onView, children, activeFilters = 0, extra }:
  { filters?: React.ReactNode; search: string; onSearch: (v: string) => void; searchLabel: string; sort?: string; onSort?: (v: string) => void;
    sortOptions?: { value: string; label: string }[]; view?: "cards" | "list"; onView?: (v: "cards" | "list") => void; children: React.ReactNode; activeFilters?: number; extra?: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={clsx("grid gap-6", filters && "lg:grid-cols-[264px_minmax(0,1fr)]")}>
      {filters && <aside className="hidden lg:block"><div className="sticky top-20 space-y-5 rounded-md border border-line bg-surface p-4">{filters}</div></aside>}
      <div className="min-w-0">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          {filters && <button onClick={() => setOpen(true)} className="inline-flex h-9 items-center gap-2 rounded-sm border border-line-strong bg-surface px-3 text-[14px] font-semibold lg:hidden"><Filter className="size-4" />Filters{activeFilters ? ` · ${activeFilters}` : ""}</button>}
          <Input className="w-full sm:w-72" prefixIcon={<Search />} placeholder={searchLabel} value={search} onChange={(e) => onSearch(e.target.value)} aria-label={searchLabel} />
          {extra}
          <div className="ml-auto flex items-center gap-2">
            {sortOptions && onSort && <label className="flex items-center gap-2 text-body-sm text-fg-muted">Sort<Select size="sm" className="w-40" value={sort!} onChange={onSort} options={sortOptions} ariaLabel="Sort" /></label>}
            {onView && <Segmented size="sm" ariaLabel="View" value={view!} onChange={onView} options={[
              { value: "cards", label: <span className="hidden lg:inline">Cards</span>, icon: <LayoutGrid /> },
              { value: "list", label: <span className="hidden lg:inline">List</span>, icon: <List /> },
            ]} />}
          </div>
        </div>
        {children}
      </div>
      {filters && <Dialog open={open} onClose={() => setOpen(false)} title="Filters" size="sm"><div className="space-y-5">{filters}</div></Dialog>}
    </div>
  );
}

export function RailGroup({ label, options, value, onChange }: { label: string; options: string[]; value: string; onChange: (v: string) => void }) {
  return (
    <div>
      <div className="mb-1.5 text-caption font-semibold text-fg-muted">{label}</div>
      <Select size="sm" value={value} onChange={onChange} ariaLabel={label} options={[{ value: "", label: `Any ${label.toLowerCase()}` }, ...options.map((o) => ({ value: o, label: o }))]} />
    </div>
  );
}

export function SeenIn({ items }: { items: { id: string; title: string; severity: Severity; status: ResearchStatus; created_at: string }[] }) {
  const wsHref = useWsHref();
  return (
    <Panel title={`Seen in research · ${items.length}`} bodyClassName="!p-0">
      {items.length ? (
        <ul className="divide-y divide-[var(--border-subtle)]">
          {items.map((r) => (
            <li key={r.id}>
              <Link href={wsHref(`/research/${r.id}`)} className="flex items-center gap-3 px-4 py-2.5 hover:bg-subtle">
                <span className="w-28 shrink-0 font-mono text-mono-sm text-fg-muted">{r.id}</span>
                <span className="min-w-0 flex-1 truncate text-[14px]">{r.title}</span>
                <SeverityBadge severity={r.severity} />
                <StatusPill status={r.status} />
                <Tooltip content={utc(r.created_at)}><span className="hidden w-20 text-right text-caption text-fg-muted sm:block">{relative(r.created_at)}</span></Tooltip>
              </Link>
            </li>
          ))}
        </ul>
      ) : <p className="p-4 text-fg-muted">Not linked to any research yet.</p>}
    </Panel>
  );
}

export function CardLink({ href, children, className }: { href: string; children: React.ReactNode; className?: string }) {
  return (
    <article className={clsx("relative flex min-w-0 flex-col gap-3 rounded-md border border-line bg-surface p-4 transition-colors hover:border-line-hover focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-[var(--focus-ring)]", className)}>
      {children}
      <Link href={href} className="absolute inset-0 focus-visible:outline-none" aria-hidden tabIndex={-1} />
    </article>
  );
}
