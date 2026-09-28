"use client";

import clsx from "clsx";
import { ArrowUpDown, ChevronDown, LayoutGrid, List, Search, SlidersHorizontal } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import { relative, utc } from "@/lib/format";
import { ActiveFilters, FilterButton, type ActiveChip, type FilterOption } from "./filters";
import { useWsHref } from "./providers";
import { SeverityBadge, StatusPill } from "./ui/badges";
import { EmptyState } from "./ui/feedback";
import { Input, Segmented } from "./ui/forms";
import { Panel } from "./ui/layout";
import { Menu, Tooltip } from "./ui/overlay";
import type { ResearchStatus, Severity } from "@/lib/types";

/* ------------------------------------------------------------------ Filter definitions */

/** One filter in a library toolbar. Rendered as a compact popover button; active values become removable chips. */
export interface FilterDef {
  key: string;
  label: string;
  options: FilterOption[];
  values: string[];
  onChange: (v: string[]) => void;
  /** Single-select: picking an option replaces the value and closes the popover. */
  single?: boolean;
}

/** Adapts a single-valued `useState<string>` to the FilterDef values/onChange shape. */
export function single(value: string, set: (v: string) => void): Pick<FilterDef, "values" | "onChange" | "single"> {
  return { values: value ? [value] : [], onChange: (v) => set(v[0] ?? ""), single: true };
}

/** Turns plain facet strings into options (label = value unless a map is given). */
export function facetOptions(values: string[] | undefined, labels?: Record<string, string>): FilterOption[] {
  return (values ?? []).map((v) => ({ value: v, label: labels?.[v] ?? v }));
}

function chipsFor(filters: FilterDef[]): ActiveChip[] {
  return filters.filter((f) => f.values.length).map((f) => ({
    key: f.key,
    label: `${f.label}: ${f.values.map((v) => f.options.find((o) => o.value === v)?.label ?? v).join(", ")}`,
    onRemove: () => f.onChange([]),
  }));
}

/** Filter panel open state, persisted per page. Defaults to open on ≥ 1280 px, collapsed below. */
export function useFilterPanel(storageKey: string) {
  const key = `tl.filters.${storageKey}`;
  const [open, setOpenState] = useState<boolean | null>(null);
  useEffect(() => {
    let v: boolean | null = null;
    try {
      const raw = localStorage.getItem(key);
      if (raw !== null) v = JSON.parse(raw) === true;
    } catch { /* ignore */ }
    setOpenState(v ?? window.innerWidth >= 1280);
  }, [key]);
  const setOpen = useCallback((v: boolean) => {
    setOpenState(v);
    try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ }
  }, [key]);
  return [open ?? false, setOpen, open !== null] as const;
}

/* ------------------------------------------------------------------ Toolbar parts */

function SortMenu({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  const current = options.find((o) => o.value === value)?.label ?? "Custom";
  return (
    <Menu align="end" width={200} items={options.map((o) => ({ label: o.label, onSelect: () => onChange(o.value), shortcut: o.value === value ? "✓" : "" }))}
      trigger={(p) => (
        <button {...p} type="button" aria-label={`Sort: ${current}`}
          className="inline-flex h-9 max-w-[220px] shrink-0 items-center gap-1.5 rounded-sm border border-line-strong bg-surface px-2.5 text-[13px] font-semibold text-fg transition-colors duration-[var(--motion-instant)] hover:border-line-hover hover:bg-subtle">
          <ArrowUpDown className="size-4 shrink-0 text-fg-muted" />
          <span className="hidden text-fg-muted sm:inline">Sort</span>
          <span className="truncate">{current}</span>
          <ChevronDown className="size-4 shrink-0 opacity-70" />
        </button>
      )} />
  );
}

function FilterToggle({ open, count, onClick, controls }: { open: boolean; count: number; onClick: () => void; controls: string }) {
  return (
    <button type="button" onClick={onClick} aria-expanded={open} aria-controls={controls}
      className={clsx("inline-flex h-9 shrink-0 items-center gap-2 rounded-sm border px-3 text-[13px] font-semibold transition-colors duration-[var(--motion-instant)]",
        open ? "border-accent bg-accent-soft text-accent-text" : "border-line-strong bg-surface text-fg hover:border-line-hover hover:bg-subtle")}>
      <SlidersHorizontal className="size-4 shrink-0" />
      Filters
      {count > 0 && (
        <span className="inline-grid h-[18px] min-w-[18px] place-items-center rounded-full bg-accent px-1.5 text-[11px] leading-none font-semibold tabular text-white">{count}</span>
      )}
    </button>
  );
}

/* ------------------------------------------------------------------ Layout */

/**
 * Shared list layout for the Research library and the four entity libraries (design.md 25.3, revised):
 * one toolbar row (search · Filters toggle · extras … sort · Cards/List), a collapsible filter bar of compact
 * popover buttons, then active-filter chips with "Clear all" and the result count. The filter bar collapses to nothing.
 */
export function LibraryLayout({
  storageKey, search, onSearch, searchLabel, filters = [], filterExtras, extraChips = [], onClearAll,
  sort, onSort, sortOptions, view, onView, total, noun, extra, toolbarOverride, children,
}: {
  /** Per-page key for remembering whether the filter bar is open. */
  storageKey: string;
  search: string; onSearch: (v: string) => void; searchLabel: string;
  filters?: FilterDef[];
  /** Non-standard controls shown in the filter bar after the filter buttons (e.g. a date range). */
  filterExtras?: React.ReactNode;
  /** Active filters that aren't FilterDefs (URL-only params such as actor or CVE). */
  extraChips?: ActiveChip[];
  /** Clears everything; defaults to clearing each FilterDef and extra chip. */
  onClearAll?: () => void;
  sort?: string; onSort?: (v: string) => void; sortOptions?: { value: string; label: string }[];
  view?: "cards" | "list"; onView?: (v: "cards" | "list") => void;
  /** Result count shown beside the chips ("24 actors"). */
  total?: number; noun?: [string, string];
  extra?: React.ReactNode;
  /** Replaces the toolbar (e.g. a bulk-selection bar). */
  toolbarOverride?: React.ReactNode;
  children: React.ReactNode;
}) {
  const [open, setOpen, ready] = useFilterPanel(storageKey);
  const panelId = useId();
  const hasFilters = filters.length > 0 || !!filterExtras;
  const chips = [...chipsFor(filters), ...extraChips];
  const clearAll = onClearAll ?? (() => { filters.forEach((f) => f.values.length && f.onChange([])); extraChips.forEach((c) => c.onRemove()); });

  return (
    <div className="min-w-0">
      {toolbarOverride ?? (
        <div className="flex flex-wrap items-center gap-2">
          <Input className="min-w-0 flex-1 basis-[200px] sm:max-w-[360px]" prefixIcon={<Search />} placeholder={searchLabel} value={search}
            onChange={(e) => onSearch(e.target.value)} aria-label={searchLabel} type="search" />
          {hasFilters && <FilterToggle open={open} count={chips.length} onClick={() => setOpen(!open)} controls={panelId} />}
          {extra}
          <div className="ml-auto flex shrink-0 items-center gap-2">
            {sortOptions && onSort && sort !== undefined && <SortMenu value={sort} onChange={onSort} options={sortOptions} />}
            {onView && view && <Segmented size="md" className="h-9" ariaLabel="View" value={view} onChange={onView} options={[
              { value: "cards", label: <span className="hidden lg:inline">Cards</span>, icon: <LayoutGrid /> },
              { value: "list", label: <span className="hidden lg:inline">List</span>, icon: <List /> },
            ]} />}
          </div>
        </div>
      )}

      {hasFilters && (
        <div id={panelId} inert={!open} aria-hidden={!open || undefined}
          className={clsx("grid", ready && "transition-[grid-template-rows,opacity] duration-[var(--motion-base)] ease-[var(--ease-standard)]", open ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0")}>
          <div className="min-h-0 overflow-hidden">
            <div role="group" aria-label="Filters" className="mt-3 flex flex-wrap items-center gap-2 rounded-md border border-line bg-surface px-3 py-2.5">
              <span className="mr-1 text-caption font-semibold text-fg-muted">Filter by</span>
              {filters.map((f) => <FilterButton key={f.key} label={f.label} options={f.options} values={f.values} onChange={f.onChange} single={f.single} />)}
              {filterExtras}
            </div>
          </div>
        </div>
      )}

      {(chips.length > 0 || total !== undefined) && (
        <div className="mt-3 flex min-h-7 flex-wrap items-center gap-x-4 gap-y-2">
          <ActiveFilters chips={chips} onClear={clearAll} className="flex-1" />
          {total !== undefined && (
            <span className="ml-auto shrink-0 text-caption tabular text-fg-muted">
              {total.toLocaleString()} {noun ? (total === 1 ? noun[0] : noun[1]) : total === 1 ? "result" : "results"}
            </span>
          )}
        </div>
      )}
      <div className="mt-4 min-w-0">{children}</div>
    </div>
  );
}

/** Responsive card grid: 1–4 columns, cards never narrower than the viewport allows (no horizontal scroll). */
export function CardGrid({ children, className, min = 300 }: { children: React.ReactNode; className?: string; min?: number }) {
  return (
    <div className={clsx("grid gap-4 md:gap-6", className)} style={{ gridTemplateColumns: `repeat(auto-fill, minmax(min(100%, ${min}px), 1fr))` }}>
      {children}
    </div>
  );
}

/** Table container: bordered surface that scrolls horizontally inside itself, never the page. */
export function TableShell({ children, footer }: { children: React.ReactNode; footer?: React.ReactNode }) {
  return (
    <div className="min-w-0 overflow-hidden rounded-md border border-line bg-surface">
      <div className="overflow-x-auto">{children}</div>
      {footer && <div className="border-t border-line">{footer}</div>}
    </div>
  );
}

/** Empty or no-match state for a library list, in a dashed surface. */
export function LibraryEmpty(props: React.ComponentProps<typeof EmptyState>) {
  return (
    <div className="rounded-md border border-dashed border-line-strong bg-surface">
      <EmptyState {...props} />
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
              <Link href={wsHref(`/research/${r.id}`)} className="flex min-w-0 items-center gap-3 px-4 py-2.5 hover:bg-subtle">
                <span className="hidden w-28 shrink-0 font-mono text-mono-sm text-fg-muted sm:block">{r.id}</span>
                <span className="min-w-0 flex-1 truncate text-[14px]" title={r.title}>{r.title}</span>
                <SeverityBadge severity={r.severity} />
                <span className="hidden sm:inline-flex"><StatusPill status={r.status} /></span>
                <Tooltip content={utc(r.created_at)}><span className="hidden w-20 shrink-0 text-right text-caption text-fg-muted md:block">{relative(r.created_at)}</span></Tooltip>
              </Link>
            </li>
          ))}
        </ul>
      ) : <p className="p-4 text-fg-muted">Not linked to any research yet.</p>}
    </Panel>
  );
}

/** Library card (design.md 14): one stretched link; inner chips stay independently focusable (wrap them in `relative z-[1]`). */
export function CardLink({ href, children, className, label }: { href: string; children: React.ReactNode; className?: string; label?: string }) {
  return (
    <article className={clsx("group relative flex min-w-0 flex-col gap-3 overflow-hidden rounded-md border border-line bg-surface p-4 transition-colors duration-[var(--motion-instant)] hover:border-line-hover focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-[var(--focus-ring)]", className)}>
      {children}
      <Link href={href} className="absolute inset-0 focus-visible:outline-none" aria-label={label} tabIndex={label ? 0 : -1} aria-hidden={label ? undefined : true} />
    </article>
  );
}

/** Card header: optional icon tile, single-line title (full text on hover), trailing badge that never pushes the title out. */
export function CardHeader({ title, icon, aside, sub }: { title: string; icon?: React.ReactNode; aside?: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <div className="flex min-w-0 items-start gap-3">
      {icon && <span className="grid size-9 shrink-0 place-items-center rounded-md bg-subtle text-fg-muted [&_svg]:size-[18px]">{icon}</span>}
      <div className="min-w-0 flex-auto">
        <h3 className="truncate text-h3 font-semibold decoration-1 underline-offset-2 group-hover:underline" title={title}>{title}</h3>
        {sub && <div className="truncate text-body-sm text-fg-muted" title={typeof sub === "string" ? sub : undefined}>{sub}</div>}
      </div>
      {/* The badge yields space before the title does. */}
      {aside && <div className="flex max-w-[50%] min-w-16 shrink-[4] justify-end pt-0.5">{aside}</div>}
    </div>
  );
}

/** Card footer: divider and caption meta, pinned to the bottom of equal-height cards. */
export function CardFooter({ children }: { children: React.ReactNode }) {
  return <div className="mt-auto flex min-w-0 items-center gap-2 border-t border-line pt-3 text-caption text-fg-muted">{children}</div>;
}
